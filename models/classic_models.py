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
fałszywych alarmów było ok. 1%. evaluate liczy recall, FPR, AUC-ROC, F1, precision i PR-AUC
(wszystkie trafiają do metrics.csv); które z nich i z jakim zastrzeżeniem idą do statystyki pracy,
opisuje stats/summarize.py. Do tego macierz pomyłek: dla każdego modelu prawdziwa klasa × decyzja
(alarm / brak alarmu), a dla RF prawdziwa klasa × przewidziana klasa (6 klas prawdziwych).
"""
from collections import Counter

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

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

# Uczy Random Forest na wszystkich przepływach, z etykietą wieloklasową i zrównoważonymi klasami.
# sample_weight (opcjonalnie): waga każdego przepływu, np. wyższa dla sesji adaptacyjnej M0 w S2.
# Z wagami przepływów class_weight="balanced" liczyłby wagi klas z liczności, a nie z sum wag, więc
# po pomnożeniu klasy ważyłyby nierówno (do 1,6× w S2). Dlatego wtedy równoważę klasy sam:
# waga przepływu × suma wszystkich wag / (liczba klas × suma wag jego klasy); każda klasa waży tyle samo.
def train_random_forest(features, attack_types, sample_weight=None):
    class_weight = "balanced"
    if sample_weight is not None:
        weights = np.asarray(sample_weight, dtype=float)
        classes, index = np.unique(attack_types, return_inverse=True)
        class_sums = np.bincount(index, weights=weights)
        sample_weight = weights * weights.sum() / (len(classes) * class_sums[index])
        class_weight = None
    model = RandomForestClassifier(
        n_estimators=200,
        class_weight=class_weight,
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


# Klasa przewidziana przez RF (do macierzy pomyłek): "normal", gdy wynik ataku 1 - P(normal) nie przekracza
# progu, a w przeciwnym razie najbardziej prawdopodobna klasa ataku. Decyzja atak / normalny jest więc ta
# sama co w metrykach binarnych. Klasy c2_beaconing RF nie zna (nie ma jej w treningu), więc jej nie przewidzi.
def random_forest_classes(model, features, threshold):
    probabilities = model.predict_proba(features)
    classes = np.array(model.classes_)
    normal_column = list(classes).index("normal")
    attack_probabilities = probabilities.copy()
    attack_probabilities[:, normal_column] = -1.0  # wybór tylko spośród klas ataków
    most_likely_attack = classes[attack_probabilities.argmax(axis=1)]
    return np.where(1.0 - probabilities[:, normal_column] > threshold, most_likely_attack, "normal")


# ---------------------------------------------------------------- próg i metryki

# Próg = wartość, której przekracza tylko ok. 1% wyników ruchu normalnego (z walidacji).
def choose_threshold(scores, labels):
    normal_scores = scores[labels == 0]
    return float(np.quantile(normal_scores, 1.0 - TARGET_FALSE_POSITIVE_RATE))


# Metryki dla etykiet binarnych (1 = atak) i wyników modelu.
#
# AUC-ROC - pole pod krzywą ROC (TPR od FPR po wszystkich progach): nie zależy od progu ani od udziału
#           ataków w teście; 0,5 = losowo, 1 = idealny ranking,
# PR-AUC  - pole pod krzywą precision-recall (zależy od udziału ataków),
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
    negatives = false_positives + true_negatives
    false_positive_rate = false_positives / negatives if negatives > 0 else 0.0
    # PR-AUC liczone jako average precision (pole pod krzywą precision-recall po wszystkich progach);
    # ma sens tylko, gdy w danych są obie klasy
    both_classes = is_attack.any() and (~is_attack).any()
    pr_auc = float(average_precision_score(labels, scores)) if both_classes else float("nan")
    roc_auc = float(roc_auc_score(labels, scores)) if both_classes else float("nan")

    return {"pr_auc": pr_auc, "roc_auc": roc_auc, "precision": precision, "recall": recall, "f1": f1,
            "fpr": false_positive_rate, "tp": true_positives, "fp": false_positives,
            "fn": false_negatives, "tn": true_negatives}


# Macierz pomyłek jako lista wierszy {true, predicted, count}: prawdziwa klasa (attack_type) × decyzja
# modelu (np. "alarm" / "brak alarmu" albo klasa przewidziana przez RF).
def confusion_rows(true_classes, predicted):
    counts = Counter(zip(true_classes, predicted))
    return [{"true": true, "predicted": decision, "count": count}
            for (true, decision), count in sorted(counts.items())]


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
