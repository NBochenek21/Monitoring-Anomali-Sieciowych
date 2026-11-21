#!/usr/bin/env python3
"""Isolation Forest i Random Forest oraz wspólny próg i metryki.

IF uczy się tylko na ruchu normalnym (100 drzew, próbka 256); wynik = jak łatwo odizolować przepływ.
RF uczy się na ruchu normalnym i atakach (200 drzew, zrównoważone klasy); wynik = 1 - P(normal),
więc działa też dla ataku, którego nie zna (Z1). Próg każdego modelu z walidacji, przy ok. 1% FPR.
evaluate liczy recall, FPR, AUC-ROC, F1, precision, PR-AUC i macierze pomyłek.
"""
from collections import Counter

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import average_precision_score, roc_auc_score

RANDOM_SEED = 42
TARGET_FALSE_POSITIVE_RATE = 0.01  #próg tak, żeby ok. 1% normalnego ruchu dawało alarm


#---------------------------------------------------------------- Isolation Forest

#uczy Isolation Forest tylko na przepływach normalnych (label == 0).
def train_isolation_forest(features, labels):
    normal_features = features[labels == 0]
    model = IsolationForest(
        n_estimators=100,   #liczba drzew
        max_samples=256,    #wielkość losowej próbki na drzewo
        random_state=RANDOM_SEED,
        n_jobs=-1,          #wszystkie rdzenie procesora
    )
    model.fit(normal_features)
    return model


#wynik anomalii: im większy, tym bardziej nietypowy przepływ.
#(score_samples w scikit-learn daje odwrotnie - mniejszy = bardziej nietypowy - więc zmieniam znak.)
def isolation_forest_scores(model, features):
    return -model.score_samples(features)


#---------------------------------------------------------------- Random Forest

#uczy Random Forest na wszystkich przepływach (wiele klas), klasy zrównoważone
#sample_weight = waga każdego przepływu (w S2 przepływy z M0 ważą więcej); wtedy wagi klas liczę sam,
#tak żeby każda klasa ważyła razem tyle samo ("balanced" liczyłby je źle, z liczności zamiast z wag)
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


#wynik ataku = 1 - prawdopodobieństwo klasy "normal".
def random_forest_scores(model, features):
    probabilities = model.predict_proba(features)
    normal_column = list(model.classes_).index("normal")
    return 1.0 - probabilities[:, normal_column]


#klasa przewidziana przez RF: "normal", gdy wynik nie przekracza progu, inaczej najbardziej prawdopodobny atak
#c2_beaconing RF nie zna (nie było go w treningu), więc nigdy go nie przewidzi
def random_forest_classes(model, features, threshold):
    probabilities = model.predict_proba(features)
    classes = np.array(model.classes_)
    normal_column = list(classes).index("normal")
    attack_probabilities = probabilities.copy()
    attack_probabilities[:, normal_column] = -1.0  #wybór tylko spośród klas ataków
    most_likely_attack = classes[attack_probabilities.argmax(axis=1)]
    return np.where(1.0 - probabilities[:, normal_column] > threshold, most_likely_attack, "normal")


#---------------------------------------------------------------- próg i metryki

#próg = wartość, której przekracza tylko ok. 1% wyników ruchu normalnego (z walidacji).
def choose_threshold(scores, labels):
    normal_scores = scores[labels == 0]
    return float(np.quantile(normal_scores, 1.0 - TARGET_FALSE_POSITIVE_RATE))


#metryki dla etykiet binarnych (1 = atak) i wyników modelu.
#
#AUC-ROC - pole pod krzywą ROC (TPR od FPR po wszystkich progach): nie zależy od progu ani od udziału
#          ataków w teście; 0,5 = losowo, 1 = idealny ranking,
#PR-AUC  - pole pod krzywą precision-recall (zależy od udziału ataków),
#precision, recall, F1, FPR - dla decyzji "wynik > próg".
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
    #PR-AUC liczone jako average precision (pole pod krzywą precision-recall po wszystkich progach);
    #ma sens tylko, gdy w danych są obie klasy
    both_classes = is_attack.any() and (~is_attack).any()
    pr_auc = float(average_precision_score(labels, scores)) if both_classes else float("nan")
    roc_auc = float(roc_auc_score(labels, scores)) if both_classes else float("nan")

    return {"pr_auc": pr_auc, "roc_auc": roc_auc, "precision": precision, "recall": recall, "f1": f1,
            "fpr": false_positive_rate, "tp": true_positives, "fp": false_positives,
            "fn": false_negatives, "tn": true_negatives}


#macierz pomyłek jako lista wierszy {true, predicted, count}: prawdziwa klasa (attack_type) x decyzja
#modelu (np. "alarm" / "brak alarmu" albo klasa przewidziana przez RF).
def confusion_rows(true_classes, predicted):
    counts = Counter(zip(true_classes, predicted))
    return [{"true": true, "predicted": decision, "count": count}
            for (true, decision), count in sorted(counts.items())]


#jaki odsetek przepływów każdego ataku przekroczył próg (wykrywalność per atak).
def recall_per_attack(attack_types, scores, threshold):
    result = {}
    for attack in sorted(set(attack_types)):
        if attack == "normal":
            continue
        mask = attack_types == attack
        result[attack] = float(np.mean(scores[mask] > threshold))
    return result


#---------------------------------------------------------------- zapis

#zapis wytrenowanego modelu scikit-learn do pliku (joblib), np. models/artifacts/S1/cic/random_forest.joblib.
def save_model(model, path):
    joblib.dump(model, path)
