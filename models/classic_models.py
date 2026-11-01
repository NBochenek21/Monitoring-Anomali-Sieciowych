#!/usr/bin/env python3
"""Modele klasyczne: Isolation Forest (wykrywanie nowości) i Random Forest (nadzorowany).

Oba modele dostają cechy przepływu (models/flow_features.py) i cechy kontekstu hosta
(features/window_features.py), po jednym przepływie na wiersz. FlowTransformer zamiast cech kontekstu
widzi okno 8 poprzednich przepływów hosta.

Isolation Forest (Liu, Ting, Zhou, ICDM 2008):
  - uczy się WYŁĄCZNIE na ruchu normalnym; nie wie, jak wyglądają ataki,
  - wynik anomalii: im łatwiej „odizolować” przepływ losowymi podziałami, tym bardziej jest nietypowy,
  - ustawienia z artykułu autorów: 100 drzew, każde na losowej próbce 256 przepływów.

Random Forest (Breiman, Machine Learning 2001):
  - uczy się na ruchu normalnym i atakach, z etykietą wieloklasową (normal, port_scan, ...),
  - wynik ataku = 1 - P(normal), dzięki czemu da się go użyć też dla ataku niewidzianego (Z1),
    którego klasy model nie zna (decyzja z planu pracy),
  - wagi klas „balanced”: rzadkie klasy ważą więcej, żeby nie zginęły przy licznym ruchu normalnym.

Próg decyzji: oba modele dają liczbę (wynik), a nie od razu decyzję „atak / normalny”.
Próg ustalam na ruchu normalnym z walidacji (dane, na których model się nie uczył) tak, żeby
fałszywych alarmów było ok. 1% (raportujemy też PR-AUC, które w ogóle nie zależy od progu).
"""
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score

RANDOM_SEED = 42
TARGET_FALSE_POSITIVE_RATE = 0.01  # próg tak, żeby ok. 1% normalnego ruchu dawało alarm


# ---------------------------------------------------------------- Isolation Forest

# Uczy Isolation Forest tylko na przepływach normalnych (label == 0).
def train_isolation_forest(features, labels):
    normal_features = features[labels == 0]
    model = IsolationForest(
        n_estimators=100,   # liczba drzew (Liu i in. 2008)
        max_samples=256,    # wielkość losowej próbki na drzewo (Liu i in. 2008)
        random_state=RANDOM_SEED,
        n_jobs=-1,          # wszystkie rdzenie procesora
    )
    model.fit(normal_features)
    return model


# Wynik anomalii: im większy, tym bardziej nietypowy przepływ.
# (score_samples w scikit-learn daje odwrotnie - mniejszy = bardziej nietypowy - więc zmieniam znak.)
def isolation_forest_scores(model, features):
    return -model.score_samples(features)


# ---------------------------------------------------------------- Random Forest

# Uczy Random Forest na wszystkich przepływach, z etykietą wieloklasową.
# sample_weight (opcjonalnie): waga każdego przepływu, np. wyższa dla sesji adaptacyjnej M0 w S2.
def train_random_forest(features, attack_types, sample_weight=None):
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight="balanced",
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    model.fit(features, attack_types, sample_weight=sample_weight)
    return model


# Wynik ataku = 1 - prawdopodobieństwo klasy „normal”.
def random_forest_scores(model, features):
    probabilities = model.predict_proba(features)
    normal_column = list(model.classes_).index("normal")
    return 1.0 - probabilities[:, normal_column]


# ---------------------------------------------------------------- próg i metryki

# Próg = wartość, której przekracza tylko ok. 1% wyników ruchu normalnego (z walidacji).
def choose_threshold(scores, labels):
    normal_scores = scores[labels == 0]
    return float(np.quantile(normal_scores, 1.0 - TARGET_FALSE_POSITIVE_RATE))


# Metryki dla etykiet binarnych (1 = atak) i wyników modelu.
#
# PR-AUC  - jakość rankingu przy niezbalansowanych klasach (nie zależy od progu),
# precision, recall, F1, FPR - dla decyzji „wynik > próg”.
def evaluate(labels, scores, threshold):
    predicted_attack = scores > threshold
    is_attack = labels == 1

    true_positives = int(np.sum(predicted_attack & is_attack))
    false_positives = int(np.sum(predicted_attack & ~is_attack))
    false_negatives = int(np.sum(~predicted_attack & is_attack))
    true_negatives = int(np.sum(~predicted_attack & ~is_attack))

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) > 0 else 0.0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    false_positive_rate = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0.0
    # PR-AUC liczone jako average precision (pole pod krzywą precision-recall po wszystkich progach);
    # ma sens tylko, gdy w danych są obie klasy
    pr_auc = float(average_precision_score(labels, scores)) if is_attack.any() and (~is_attack).any() else float("nan")

    return {"pr_auc": pr_auc, "precision": precision, "recall": recall, "f1": f1,
            "fpr": false_positive_rate, "tp": true_positives, "fp": false_positives,
            "fn": false_negatives, "tn": true_negatives}


# Jaki odsetek przepływów każdego ataku przekroczył próg (wykrywalność per atak).
def recall_per_attack(attack_types, scores, threshold):
    result = {}
    for attack in sorted(set(attack_types)):
        if attack == "normal":
            continue
        mask = attack_types == attack
        result[attack] = float(np.mean(scores[mask] > threshold))
    return result


# ---------------------------------------------------------------- zapis

# Zapis wytrenowanego modelu scikit-learn do pliku (joblib), np. models/artifacts/S1/cic/random_forest.joblib.
def save_model(model, path):
    joblib.dump(model, path)
