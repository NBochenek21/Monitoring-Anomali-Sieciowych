#!/usr/bin/env python3
"""Eksperymenty S0 i S1 dla wszystkich modeli: baseline, Isolation Forest, Random Forest, FlowTransformer.

S0 - trening i test na zbiorze źródłowym (ta sama domena, punkt odniesienia),
S1 - trening na całym zbiorze źródłowym, test na sesjach z Mininetu (transfer bezpośredni).

Podział w S0: podział po nagraniach (dniach) wyrzuciłby całe ataki z treningu albo z testu, bo
każdy atak jest tylko w jednym nagraniu, a w CIC ataki z jednego dnia mają osobne okna czasowe.
Dzielę więc w czasie każdy fragment = (nagranie, klasa): pierwsze 70% przepływów to trening,
ostatnie 30% to test. Bez losowania, więc prawie identyczne sąsiednie przepływy nie trafiają
jednocześnie do treningu i do testu (Arp i in. 2022, pułapka P3).

Walidacja: ostatnie 15% (w czasie) każdego fragmentu części treningowej. Na niej wyznaczam próg
każdego modelu (ok. 1% FPR) i zatrzymuję trening FlowTransformera; modele się na niej nie uczą.
Przepływy "attempted" (atak bez danych od atakującego) i "poza_zakresem" usuwam z treningu i testu.

Dwa warianty zbioru źródłowego (wariant = nazwy plików z --source połączone "+"):
  sam CIC-IDS2017:  --source data/flows/cic.parquet
  CIC + GeNIS:      --source data/flows/cic.parquet data/flows/genis.parquet
Przy kilku plikach zbiory są sklejane (każdy z kolumną source), a próbka ma stały limit na każdą parę
(źródło, klasa), więc każdy zbiór daje tyle samo przepływów danej klasy (o ile ma ich dość).

Wszystkie modele uczą się na tej samej próbce: najwyżej 20 000 przepływów z każdej pary (źródło, klasa).
Cechy okienkowe i okna FlowTransformera liczę wcześniej, na pełnych danych.
IF, RF i baseline dostają cechy przepływu + cechy okienkowe; FlowTransformer tylko cechy przepływu,
bo kontekst hosta daje mu okno 8 poprzednich przepływów.

Wyniki:
  results/S0_S1/<wariant>/metrics.csv            - metryki i koszt dla każdego scenariusza, zbioru testowego i modelu,
  results/S0_S1/<wariant>/recall_per_attack.csv  - recall osobno dla każdego ataku,
  results/raw/S1_<wariant>_<sesja>/              - predykcje S1 w formacie dashboardu (app/dashboard.py),
  models/artifacts/S1/<wariant>/                 - modele z S1 (do S2).
W S0 test jest liczony osobno dla każdego źródła, więc oba warianty da się porównać na tym samym teście CIC.

    /root/venvs/ft/bin/python models/run_experiments.py --source data/flows/genis.parquet \
        --sessions data/flows/T_check.parquet
"""
import argparse
import json
import os
import sys
import time

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "features"))

import keras  # noqa: E402
import baseline_model  # noqa: E402
import classic_models  # noqa: E402
import flow_features  # noqa: E402
import flowtransformer_model as ftm  # noqa: E402
from window_features import WINDOW_FEATURES, add_window_features  # noqa: E402

RANDOM_SEED = 42
FLOWS_PER_CLASS = 20000
TRAINING_SHARE_S0 = 0.7
VALIDATION_SHARE = 0.15  # końcówka treningu (w czasie): progi wszystkich modeli i zatrzymanie FT
NOT_USED = ["poza_zakresem", "attempted"]  # klasy usuwane z treningu i testu
MAX_EPOCHS = 20
PATIENCE = 3             # ile epok bez poprawy PR-AUC na walidacji, zanim trening się zatrzyma
BATCH_SIZE = 128
MODELS = ["baseline", "IF", "RF", "FT"]
IOT_IP = "10.0.1.17"  # q2, heartbeat IoT (env/topology.py): legalna regularność, trudny przypadek dla Z1

PREDICTION_COLUMNS = ["bidirectional_first_seen_ms", "src_ip", "dst_ip", "dst_port", "protocol",
                      "attack_type", "label"]


# ---------------------------------------------------------------- podział i próbka

# Pozycja przepływu w czasie w jego fragmencie: od 0 (pierwszy) do 1 (ostatni).
#
# Fragment = jedna klasa w jednym nagraniu (np. slowloris w środę CIC albo ruch normalny w środę).
# Dzięki temu każdy atak trafia częściowo do treningu i częściowo do testu, nawet gdy w nagraniu
# ataki idą jeden po drugim (w CIC ataki z jednego dnia mają osobne okna czasowe).
def time_position(flows):
    groups = ["attack_type"]
    if "recording" in flows.columns:
        groups = ["recording", "attack_type"]
    # rank(pct=True) = miejsce przepływu w kolejności startu w jego fragmencie jako ułamek (1/n ... 1);
    # method="first" daje różne miejsca także przy tym samym czasie startu
    ranks = flows.groupby(groups)["bidirectional_first_seen_ms"].rank(method="first", pct=True)
    return ranks.to_numpy()


# Podział w czasie: pierwsze first_share przepływów każdego fragmentu i reszta (np. 70% / 30% w S0).
def split_in_time(flows, first_share):
    is_first = time_position(flows) <= first_share
    return flows[is_first].reset_index(drop=True), flows[~is_first].reset_index(drop=True)


# Prawda dla przepływów z próbki: najwyżej FLOWS_PER_CLASS z każdej pary (źródło, klasa).
def sample_mask(flows):
    generator = np.random.default_rng(RANDOM_SEED)
    in_sample = np.zeros(len(flows), dtype=bool)
    groups = flows.groupby(["source", "attack_type"]).indices  # para -> numery jej wierszy
    for key in sorted(groups):  # stała kolejność = ta sama próbka przy każdym uruchomieniu
        rows = groups[key]
        if len(rows) > FLOWS_PER_CLASS:
            rows = generator.choice(rows, FLOWS_PER_CLASS, replace=False)
        in_sample[rows] = True
    return in_sample


# Wczytuje zbiory źródłowe i skleja je w jedną tabelę.
#
# Cechy okienkowe liczę w każdym zbiorze osobno, na pełnych danych (także z ruchem spoza zakresu),
# dopiero potem usuwam ten ruch. Nazwę nagrania poprzedzam nazwą źródła, żeby okna z dwóch zbiorów
# nigdy się nie połączyły.
def load_source(paths):
    parts = []
    for path in paths:
        flows = pd.read_parquet(path)
        if "source" not in flows.columns:
            flows["source"] = os.path.basename(path).replace(".parquet", "")
        if "recording" not in flows.columns:
            flows["recording"] = "all"
        flows["recording"] = flows["source"] + "/" + flows["recording"].astype(str)
        flows = add_window_features(flows)
        print("Usuwane z", path, flows[flows["attack_type"].isin(NOT_USED)]["attack_type"].value_counts().to_dict())
        parts.append(flows[~flows["attack_type"].isin(NOT_USED)])
    return pd.concat(parts, ignore_index=True)


# Sesja z Mininetu: cechy okienkowe na pełnych danych, potem bez klas spoza treningu.
def load_session(path):
    flows = add_window_features(pd.read_parquet(path))
    flows = flows[~flows["attack_type"].isin(NOT_USED)].reset_index(drop=True)
    flows["source"] = "mininet"
    return flows


# ---------------------------------------------------------------- FlowTransformer

# Okna FlowTransformera dla tabeli przepływów: najpierw cechy przepływu (przygotowanie z treningu),
# potem dla każdego przepływu okno 8 ostatnich przepływów jego hosta (flowtransformer_model.py).
def flowtransformer_windows(flows, preprocessing):
    return ftm.build_windows(flows, flow_features.transform_flows(flows, preprocessing))


# Okna z pełnych danych (kontekst hosta), potem tylko okna przepływów z próbki.
def sampled_windows(flows, in_sample, preprocessing, spec):
    windows, labels, rows = flowtransformer_windows(flows, preprocessing)
    keep = in_sample[rows]  # rows[i] = numer wiersza, którego ostatnim przepływem jest okno i
    return ftm.windows_to_model_inputs(windows[keep], spec), labels[keep]


# Wagi klas: klasa rzadsza waży więcej, żeby nie ginęła przy licznym ruchu normalnym.
# Wzór jak class_weight="balanced" w scikit-learn: n / (2 * liczność klasy), więc przy 50/50 obie wagi = 1.
def balanced_class_weight(labels):
    attacks = labels.sum()
    normals = len(labels) - attacks
    return {0: len(labels) / (2 * normals), 1: len(labels) / (2 * attacks)}


# Trening (albo dostrajanie) z wczesnym zatrzymaniem na walidacji; próg z walidacji.
# Zwraca (próg, liczba epok).
def fit_flowtransformer(model, train_inputs, train_labels, validation_inputs, validation_labels, max_epochs):
    stop = keras.callbacks.EarlyStopping(monitor="val_pr_auc", mode="max", patience=PATIENCE,
                                         restore_best_weights=True)
    history = model.fit(train_inputs, train_labels, validation_data=(validation_inputs, validation_labels),
                        epochs=max_epochs, batch_size=BATCH_SIZE, class_weight=balanced_class_weight(train_labels),
                        callbacks=[stop], verbose=2)
    # próg z walidacji, nie z danych, na których model się uczył (Arp i in. 2022, pułapka P5)
    validation_scores = model.predict(validation_inputs, batch_size=1024, verbose=0).reshape(-1)
    return classic_models.choose_threshold(validation_scores, validation_labels), len(history.epoch)


# Trening FlowTransformera od zera: przygotowanie cech dopasowane na części do uczenia, okna z pełnych
# danych, a do treningu i walidacji tylko okna przepływów z próbki. Zwraca (model, przygotowanie, próg, epoki).
def train_flowtransformer(train_part, train_sample, validation, validation_sample):
    keras.utils.set_random_seed(RANDOM_SEED)  # ta sama inicjalizacja wag przy każdym uruchomieniu
    # FT nie dostaje cech kontekstu hosta: kontekst daje mu okno 8 poprzednich przepływów
    train_part = train_part.drop(columns=WINDOW_FEATURES)
    validation = validation.drop(columns=WINDOW_FEATURES)
    preprocessing = flow_features.fit_preprocessing(train_part)
    spec = ftm.model_input_specification(preprocessing)
    train_inputs, train_labels = sampled_windows(train_part, train_sample, preprocessing, spec)
    validation_inputs, validation_labels = sampled_windows(validation, validation_sample, preprocessing, spec)
    model = ftm.build_model(preprocessing)
    threshold, epochs = fit_flowtransformer(model, train_inputs, train_labels, validation_inputs, validation_labels,
                                            MAX_EPOCHS)
    return model, preprocessing, threshold, epochs


# Wynik FT (prawdopodobieństwo ataku) dla każdego przepływu tabeli, w kolejności jej wierszy.
def flowtransformer_scores(model, preprocessing, flows):
    windows, _, rows = flowtransformer_windows(flows.drop(columns=WINDOW_FEATURES), preprocessing)
    spec = ftm.model_input_specification(preprocessing)
    predictions = model.predict(ftm.windows_to_model_inputs(windows, spec), batch_size=1024, verbose=0).reshape(-1)
    # okna są w kolejności (host, czas), więc wyniki wracają na miejsca swoich wierszy
    scores = np.zeros(len(flows))
    scores[rows] = predictions
    return scores


# ---------------------------------------------------------------- trening i wyniki wszystkich modeli

# Baseline, Isolation Forest i Random Forest; progi z walidacji (ok. 1% FPR).
#
# training / features      - przepływy do uczenia i ich cechy (te same wiersze),
# baseline_training        - przepływy, z których baseline bierze progi (domyślnie training),
# sample_weight            - wagi przepływów dla Random Forest (S2: M0 waży tyle, co źródło).
def train_classic(training, features, validation_flows, validation_features, baseline_training=None,
                  sample_weight=None):
    labels = training["label"].to_numpy()
    validation_labels = validation_flows["label"].to_numpy()
    if baseline_training is None:
        baseline_training = training
    models = {}

    start = time.time()
    limits = baseline_model.fit_baseline(baseline_training)
    models["baseline"] = {"model": limits, "train_seconds": time.time() - start}
    validation_scores = baseline_model.baseline_scores(validation_flows, limits)
    models["baseline"]["threshold"] = classic_models.choose_threshold(validation_scores, validation_labels)

    start = time.time()
    model = classic_models.train_isolation_forest(features, labels)
    models["IF"] = {"model": model, "train_seconds": time.time() - start}
    validation_scores = classic_models.isolation_forest_scores(model, validation_features)
    models["IF"]["threshold"] = classic_models.choose_threshold(validation_scores, validation_labels)

    start = time.time()
    model = classic_models.train_random_forest(features, training["attack_type"].to_numpy(), sample_weight)
    models["RF"] = {"model": model, "train_seconds": time.time() - start}
    validation_scores = classic_models.random_forest_scores(model, validation_features)
    models["RF"]["threshold"] = classic_models.choose_threshold(validation_scores, validation_labels)
    return models


# Uczy wszystkie modele na tej samej próbce, a progi wyznacza na walidacji.
#
# Walidacja = ostatnie 15% (w czasie) każdego fragmentu części treningowej. Model się na niej nie
# uczy; służy do progu przy ok. 1% FPR i do wczesnego zatrzymania FlowTransformera.
def train_all(training_flows):
    in_train_part = time_position(training_flows) <= 1 - VALIDATION_SHARE
    train_part = training_flows[in_train_part].reset_index(drop=True)
    validation = training_flows[~in_train_part].reset_index(drop=True)
    train_sample = sample_mask(train_part)
    validation_sample = sample_mask(validation)

    sample = train_part[train_sample].reset_index(drop=True)
    validation_flows = validation[validation_sample].reset_index(drop=True)
    print("Próbka treningowa:", sample.groupby(["source", "attack_type"]).size().to_dict())
    print("Walidacja (progi):", validation_flows.groupby(["source", "attack_type"]).size().to_dict())

    # IF i RF: cechy przepływu + cechy okienkowe (preprocessing z części do uczenia)
    preprocessing = flow_features.fit_preprocessing(train_part)
    models = train_classic(sample, flow_features.transform_flows(sample, preprocessing), validation_flows,
                           flow_features.transform_flows(validation_flows, preprocessing))

    start = time.time()
    model, ft_preprocessing, threshold, epochs = train_flowtransformer(train_part, train_sample,
                                                                       validation, validation_sample)
    models["FT"] = {"model": model, "threshold": threshold, "train_seconds": time.time() - start,
                    "preprocessing": ft_preprocessing, "epochs": epochs}

    models["preprocessing"] = preprocessing
    return models


# Wyniki jednego modelu (baseline, IF, RF albo FT) dla tabeli przepływów; większy wynik = bardziej atak.
def model_scores(name, models, flows):
    if name == "baseline":
        return baseline_model.baseline_scores(flows, models["baseline"]["model"])
    if name == "FT":
        return flowtransformer_scores(models["FT"]["model"], models["FT"]["preprocessing"], flows)
    features = flow_features.transform_flows(flows, models["preprocessing"])
    if name == "IF":
        return classic_models.isolation_forest_scores(models["IF"]["model"], features)
    return classic_models.random_forest_scores(models["RF"]["model"], features)


# Wyniki wszystkich modeli na każdym zbiorze testowym. Zwraca (metryki, recall per atak, wyniki).
def evaluate_all(scenario, models, test_sets):
    metric_rows = []
    attack_rows = []
    all_scores = {}
    for test_name, test_flows in test_sets.items():
        labels = test_flows["label"].to_numpy()
        attack_types = test_flows["attack_type"].to_numpy()
        all_scores[test_name] = {}
        for name in MODELS:
            start = time.time()
            scores = model_scores(name, models, test_flows)
            seconds = time.time() - start
            all_scores[test_name][name] = scores
            threshold = models[name]["threshold"]
            result = classic_models.evaluate(labels, scores, threshold)
            # FPR liczony tylko na ruchu normalnym hosta IoT: jak często legalny heartbeat wygląda na atak
            iot_normal = (test_flows["src_ip"] == IOT_IP).to_numpy() & (labels == 0)
            fpr_iot = float(np.mean(scores[iot_normal] > threshold)) if iot_normal.any() else float("nan")
            metric_rows.append({
                "scenario": scenario, "test": test_name, "model": name,
                "flows": len(test_flows), "attack_share": round(float(labels.mean()), 3),
                "pr_auc": round(result["pr_auc"], 3), "precision": round(result["precision"], 3),
                "recall": round(result["recall"], 3), "f1": round(result["f1"], 3), "fpr": round(result["fpr"], 3),
                "fpr_iot": round(fpr_iot, 3), "tp": result["tp"], "fp": result["fp"], "fn": result["fn"], "tn": result["tn"],
                "threshold": threshold, "train_seconds": round(models[name]["train_seconds"], 1),
                "flows_per_second": round(len(test_flows) / max(seconds, 1e-6)),
            })
            for attack, recall in classic_models.recall_per_attack(attack_types, scores, threshold).items():
                attack_rows.append({"scenario": scenario, "test": test_name, "model": name,
                                    "attack": attack, "recall": round(recall, 3)})
    return metric_rows, attack_rows, all_scores


# ---------------------------------------------------------------- zapis

# Zapis modeli z S1 do models/artifacts/S1/<wariant>/: progi baseline'u, IF i RF (joblib), oba
# przygotowania cech (JSON), wagi FT i progi. run_s2.py wczytuje stąd wagi FT do dostrajania.
def save_s1_models(models, folder):
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, "baseline_limits.json"), "w") as f:
        json.dump(models["baseline"]["model"], f, indent=2)
    classic_models.save_model(models["IF"]["model"], os.path.join(folder, "isolation_forest.joblib"))
    classic_models.save_model(models["RF"]["model"], os.path.join(folder, "random_forest.joblib"))
    flow_features.save_preprocessing(models["preprocessing"], os.path.join(folder, "preprocessing_classic.json"))
    flow_features.save_preprocessing(models["FT"]["preprocessing"], os.path.join(folder, "preprocessing_ft.json"))
    models["FT"]["model"].save_weights(os.path.join(folder, "flowtransformer.weights.h5"))
    thresholds = {name: models[name]["threshold"] for name in MODELS}
    with open(os.path.join(folder, "thresholds.json"), "w") as f:
        json.dump(thresholds, f, indent=2)


# Format, który czyta app/dashboard.py: przepływy, wyniki modeli, progi i opis biegu
# (scenariusz S1 albo S2, sesja, wariant zbioru źródłowego). Używa go też run_s2.py.
def save_dashboard_predictions(test_flows, scores, models, folder, session, source, scenario="S1"):
    os.makedirs(folder, exist_ok=True)
    out = test_flows[PREDICTION_COLUMNS].copy()
    for name in MODELS:
        out[f"score_{name}"] = scores[name]
    out.sort_values("bidirectional_first_seen_ms").to_parquet(os.path.join(folder, "predictions.parquet"), index=False)
    with open(os.path.join(folder, "thresholds.json"), "w") as f:
        json.dump({name: models[name]["threshold"] for name in MODELS}, f, indent=2)
    with open(os.path.join(folder, "info.json"), "w") as f:
        json.dump({"scenario": scenario, "session": session, "source": source}, f, indent=2)


# S0 i S1 po kolei dla jednego wariantu zbioru źródłowego; wyniki do results/S0_S1/<wariant>/,
# predykcje S1 dla dashboardu do results/raw/, modele S1 do models/artifacts/.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", nargs="+", required=True,
                        help="zbiór źródłowy: jeden plik (np. sam CIC) albo kilka (np. CIC + GeNIS)")
    parser.add_argument("--sessions", nargs="+", required=True, help="sesje z Mininetu do S1")
    args = parser.parse_args()

    # nazwa wariantu z nazw plików, np. "cic" albo "cic+genis"
    variant = "+".join(os.path.basename(path).replace(".parquet", "") for path in args.source)
    source = load_source(args.source)
    sessions = {}
    for path in args.sessions:
        sessions[os.path.basename(path).replace(".parquet", "")] = load_session(path)

    print("\n=== S0: trening i test na zbiorze źródłowym ===")
    training, test = split_in_time(source, TRAINING_SHARE_S0)
    models = train_all(training)
    # test S0 osobno dla każdego źródła, żeby oba warianty dało się porównać na tym samym teście CIC
    test_sets = {}
    for name in sorted(test["source"].unique()):
        test_sets[f"{name}_test"] = test[test["source"] == name].reset_index(drop=True)
    s0_metrics, s0_attacks, _ = evaluate_all("S0", models, test_sets)

    print("\n=== S1: trening na całym zbiorze źródłowym, test na Mininecie ===")
    models = train_all(source)  # modele uczone od nowa, tym razem na całym źródle (bez podziału 70/30)
    s1_metrics, s1_attacks, s1_scores = evaluate_all("S1", models, sessions)
    save_s1_models(models, os.path.join(HERE, "artifacts", "S1", variant))
    for session, flows in sessions.items():
        save_dashboard_predictions(flows, s1_scores[session], models,
                                   os.path.join(RESULTS, "raw", f"S1_{variant}_{session}"), session, variant)

    folder = os.path.join(RESULTS, "S0_S1", variant)
    os.makedirs(folder, exist_ok=True)
    metrics = pd.DataFrame(s0_metrics + s1_metrics)
    metrics.insert(0, "variant", variant)
    metrics.to_csv(os.path.join(folder, "metrics.csv"), index=False)
    pd.DataFrame(s0_attacks + s1_attacks).to_csv(os.path.join(folder, "recall_per_attack.csv"), index=False)
    print("\nEpoki FlowTransformera w S1:", models["FT"]["epochs"])
    print(metrics[["scenario", "test", "model", "attack_share", "pr_auc", "precision", "recall", "f1", "fpr",
                   "fpr_iot", "train_seconds", "flows_per_second"]].to_string(index=False))


if __name__ == "__main__":
    main()
