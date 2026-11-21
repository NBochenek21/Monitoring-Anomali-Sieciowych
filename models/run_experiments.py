#!/usr/bin/env python3
r"""Eksperymenty S0 i S1 dla baseline, Isolation Forest, Random Forest i FlowTransformera.

S0: trening i test na zbiorze źródłowym (pierwsze 70% w czasie / ostatnie 30%, osobno w każdej parze
(nagranie, klasa), a nie na wspólnej osi czasu), punkt odniesienia.
S1: trening na całym zbiorze źródłowym, test na sesjach M1-M6 z Mininetu.
Walidacja = ostatnie 15% części treningowej (progi przy ok. 1% FPR, zatrzymanie FT). Próbka: najwyżej
20 000 przepływów na parę (źródło, klasa). Wyniki do results/S0_S1/<wariant>/ i results/raw/,
modele S1 do models/artifacts/S1/<wariant>/ (dla run_s2.py).

    /root/venvs/ft/bin/python models/run_experiments.py --source data/flows/cic.parquet \
        --sessions data/flows/M1.parquet data/flows/M2.parquet
    (wariant CIC + GeNIS: --source data/flows/cic.parquet data/flows/genis.parquet)
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

import keras  #noqa: E402
import baseline_model  #noqa: E402
import classic_models  #noqa: E402
import flow_features  #noqa: E402
import flowtransformer_model as ftm  #noqa: E402
from window_features import WINDOW_FEATURES, add_window_features  #noqa: E402

RANDOM_SEED = 42
FLOWS_PER_CLASS = 20000
TRAINING_SHARE_S0 = 0.7
VALIDATION_SHARE = 0.15  #końcówka treningu (w czasie): progi wszystkich modeli i zatrzymanie FT
NOT_USED = ["poza_zakresem", "attempted"]  #klasy usuwane z treningu i testu
MAX_EPOCHS = 20
PATIENCE = 3             #ile epok bez poprawy PR-AUC na walidacji, zanim trening się zatrzyma
BATCH_SIZE = 128
MODELS = ["baseline", "IF", "RF", "FT"]
PREDICT_CHUNK = 200_000  #tyle okien FT naraz przy predykcji (ogranicza zużycie pamięci)
IOT_IP = "10.0.1.17"  #q2, heartbeat IoT (env/topology.py): legalna regularność, trudny przypadek dla Z1

#koniec przepływu (ostatni pakiet): dashboard liczy od niego opóźnienie detekcji (wynik modelu jest znany
#dopiero po eksporcie przepływu, a nie w chwili jego startu; przy zamknięciu po 60 s bezczynności
#eksport jest jeszcze ok. 60 s później, więc opóźnienie jest tu oszacowaniem z dołu)
PREDICTION_COLUMNS = ["bidirectional_first_seen_ms", "bidirectional_last_seen_ms", "src_ip", "dst_ip",
                      "dst_port", "protocol", "attack_type", "label"]


#---------------------------------------------------------------- podział i próbka

#miejsce przepływu w czasie w jego fragmencie: od 0 (pierwszy) do 1 (ostatni)
#fragment = jedna klasa w jednym nagraniu (np. slowloris w środę CIC), więc każdy atak trafia
#częściowo do treningu i częściowo do testu; podział nie idzie po wspólnej osi czasu (np. testowy
#slowloris ze środy jest wcześniejszy niż część treningowego ruchu normalnego z tego dnia)
def time_position(flows):
    groups = ["attack_type"]
    if "recording" in flows.columns:
        groups = ["recording", "attack_type"]
    #miejsce w kolejności startu jako ułamek (1/n ... 1); przy tym samym czasie startu każdy dostaje inne miejsce
    ranks = flows.groupby(groups)["bidirectional_first_seen_ms"].rank(method="first", pct=True)
    return ranks.to_numpy()


#podział w czasie: pierwsze first_share przepływów każdego fragmentu i reszta (np. 70% / 30% w S0)
def split_in_time(flows, first_share):
    is_first = time_position(flows) <= first_share
    return flows[is_first].reset_index(drop=True), flows[~is_first].reset_index(drop=True)


#wybór próbki: najwyżej 20 000 przepływów z każdej pary (źródło, klasa), zawsze ta sama
def sample_mask(flows):
    generator = np.random.default_rng(RANDOM_SEED)
    in_sample = np.zeros(len(flows), dtype=bool)
    groups = flows.groupby(["source", "attack_type"]).indices  #para -> numery jej wierszy
    for key in sorted(groups):  #stała kolejność = ta sama próbka przy każdym uruchomieniu
        rows = groups[key]
        if len(rows) > FLOWS_PER_CLASS:
            rows = generator.choice(rows, FLOWS_PER_CLASS, replace=False)
        in_sample[rows] = True
    return in_sample


#dodaje kolumnę row = numer wiersza w pełnej tabeli; po niej okno FT znajduje historię hosta
def numbered(flows):
    flows = flows.reset_index(drop=True)
    flows["row"] = np.arange(len(flows))
    return flows


#przepływy do treningu i testu: bez attempted i poza_zakresem (zostają tylko jako historia hosta)
def usable(full):
    removed = full[full["attack_type"].isin(NOT_USED)]["attack_type"]
    print("Usuwane z treningu i testu:", removed.value_counts().to_dict())
    return full[~full["attack_type"].isin(NOT_USED)].reset_index(drop=True)


#wczytuje zbiory źródłowe i skleja w jedną pełną tabelę (razem z attempted i poza_zakresem)
#cechy kontekstu liczę w każdym zbiorze osobno; nazwa nagrania dostaje przedrostek źródła,
#żeby historia hosta nie mieszała dwóch zbiorów
def load_source(paths):
    parts = []
    for path in paths:
        flows = pd.read_parquet(path)
        if "source" not in flows.columns:
            flows["source"] = os.path.basename(path).replace(".parquet", "")
        if "recording" not in flows.columns:
            flows["recording"] = "all"
        flows["recording"] = flows["source"] + "/" + flows["recording"].astype(str)
        parts.append(add_window_features(flows))
    return numbered(pd.concat(parts, ignore_index=True))


#sesja z Mininetu jako pełna tabela z cechami kontekstu
def load_session(path):
    flows = add_window_features(pd.read_parquet(path))
    flows["source"] = "mininet"
    return numbered(flows)


#---------------------------------------------------------------- FlowTransformer

#wejście FT: dla każdego przepływu okno 8 ostatnich przepływów jego hosta (z pełnej tabeli full)
def flowtransformer_inputs(full, flows, preprocessing, spec):
    windows, labels = ftm.build_windows(full, flows["row"].to_numpy(),
                                        lambda part: flow_features.transform_flows(part, preprocessing))
    return ftm.windows_to_model_inputs(windows, spec), labels


#wagi klas: rzadsza klasa waży więcej, żeby nie zginęła (wzór n / (2 * liczność klasy), jak "balanced")
def balanced_class_weight(labels):
    attacks = labels.sum()
    normals = len(labels) - attacks
    return {0: len(labels) / (2 * normals), 1: len(labels) / (2 * attacks)}


#trening albo dostrajanie FT: stop po 3 epokach bez poprawy na walidacji, potem próg z walidacji
#zwraca próg i epoki (ile przebiegów i z której epoki są wagi - Keras przywraca najlepsze wagi)
def fit_flowtransformer(model, train_inputs, train_labels, validation_inputs, validation_labels, max_epochs):
    stop = keras.callbacks.EarlyStopping(monitor="val_pr_auc", mode="max", patience=PATIENCE,
                                         restore_best_weights=True)
    start = time.time()
    history = model.fit(train_inputs, train_labels, validation_data=(validation_inputs, validation_labels),
                        epochs=max_epochs, batch_size=BATCH_SIZE, class_weight=balanced_class_weight(train_labels),
                        callbacks=[stop], verbose=2)
    fit_seconds = time.time() - start  #czas treningu FT = sam fit, jak dla IF i RF
    #próg z walidacji, nie z danych, na których model się uczył
    validation_scores = model.predict(validation_inputs, batch_size=1024, verbose=0).reshape(-1)
    epochs = {"runs": len(history.epoch), "best": int(stop.best_epoch) + 1,  #best_epoch liczy od 0
              "fit_seconds": fit_seconds}
    return classic_models.choose_threshold(validation_scores, validation_labels), epochs


#trening FT od zera: przygotowanie cech z części do uczenia, okna dla próbki i walidacji, trening, próg
def train_flowtransformer(train_part, sample, validation_flows, full):
    keras.utils.set_random_seed(RANDOM_SEED)  #ta sama inicjalizacja wag przy każdym uruchomieniu
    #FT nie dostaje cech kontekstu hosta: kontekst daje mu okno (7 poprzednich przepływów hosta i bieżący)
    preprocessing = flow_features.fit_preprocessing(train_part.drop(columns=WINDOW_FEATURES))
    spec = ftm.model_input_specification(preprocessing)
    train_inputs, train_labels = flowtransformer_inputs(full, sample, preprocessing, spec)
    validation_inputs, validation_labels = flowtransformer_inputs(full, validation_flows, preprocessing, spec)
    model = ftm.build_model(preprocessing)
    threshold, epochs = fit_flowtransformer(model, train_inputs, train_labels, validation_inputs, validation_labels,
                                            MAX_EPOCHS)
    return model, preprocessing, threshold, epochs


#wynik FT (prawdopodobieństwo ataku) dla każdego przepływu; po 200 000 naraz, żeby starczyło pamięci
def flowtransformer_scores(model, preprocessing, flows, full):
    spec = ftm.model_input_specification(preprocessing)
    scores = []
    for start in range(0, len(flows), PREDICT_CHUNK):
        inputs, _ = flowtransformer_inputs(full, flows.iloc[start:start + PREDICT_CHUNK], preprocessing, spec)
        scores.append(model.predict(inputs, batch_size=1024, verbose=0).reshape(-1))
    return np.concatenate(scores) if scores else np.zeros(0)


#---------------------------------------------------------------- trening i wyniki wszystkich modeli

#uczy baseline, IF i RF, a każdemu ustawia próg na walidacji (ok. 1% FPR)
#train_seconds = sam fit (bez przygotowania cech i wyboru progu), tak samo jak dla FT
#baseline_training = skąd baseline bierze progi (w S2 tylko M0), sample_weight = wagi przepływów dla RF
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


#dzieli na część do uczenia i walidację (ostatnie 15% w czasie) i z obu wybiera próbkę
#run_s2.py używa tej funkcji, żeby mieć tę samą próbkę źródła co w S1
def split_and_sample(flows):
    in_train_part = time_position(flows) <= 1 - VALIDATION_SHARE
    train_part = flows[in_train_part].reset_index(drop=True)
    validation = flows[~in_train_part].reset_index(drop=True)
    sample = train_part[sample_mask(train_part)].reset_index(drop=True)
    validation_flows = validation[sample_mask(validation)].reset_index(drop=True)
    return train_part, sample, validation_flows


#uczy wszystkie modele na tej samej próbce; walidacja (na niej model się nie uczy) daje progi
#i moment zatrzymania treningu FT
def train_all(training_flows, full):
    train_part, sample, validation_flows = split_and_sample(training_flows)
    print("Próbka treningowa:", sample.groupby(["source", "attack_type"]).size().to_dict())
    print("Walidacja (progi):", validation_flows.groupby(["source", "attack_type"]).size().to_dict())

    #IF i RF: cechy przepływu + cechy okienkowe (preprocessing z części do uczenia)
    preprocessing = flow_features.fit_preprocessing(train_part)
    models = train_classic(sample, flow_features.transform_flows(sample, preprocessing), validation_flows,
                           flow_features.transform_flows(validation_flows, preprocessing))

    model, ft_preprocessing, threshold, epochs = train_flowtransformer(train_part, sample, validation_flows, full)
    models["FT"] = {"model": model, "threshold": threshold, "train_seconds": epochs["fit_seconds"],
                    "preprocessing": ft_preprocessing, "epochs": epochs}

    models["preprocessing"] = preprocessing
    return models


#wyniki jednego modelu dla przepływów; większy wynik = bardziej podobne do ataku
def model_scores(name, models, flows, full):
    if name == "baseline":
        return baseline_model.baseline_scores(flows, models["baseline"]["model"])
    if name == "FT":
        return flowtransformer_scores(models["FT"]["model"], models["FT"]["preprocessing"], flows, full)
    features = flow_features.transform_flows(flows, models["preprocessing"])
    if name == "IF":
        return classic_models.isolation_forest_scores(models["IF"]["model"], features)
    return classic_models.random_forest_scores(models["RF"]["model"], features)


#testuje wszystkie modele na każdym zbiorze testowym: metryki, recall każdego ataku, macierze pomyłek
#macierz: prawdziwa klasa x alarm / brak alarmu, a dla RF też prawdziwa klasa x przewidziana klasa
def evaluate_all(scenario, models, test_sets):
    metric_rows = []
    attack_rows = []
    confusion = []
    all_scores = {}
    for test_name, (test_flows, full) in test_sets.items():
        labels = test_flows["label"].to_numpy()
        attack_types = test_flows["attack_type"].to_numpy()
        all_scores[test_name] = {}
        for name in MODELS:
            start = time.time()
            scores = model_scores(name, models, test_flows, full)
            seconds = time.time() - start
            all_scores[test_name][name] = scores
            threshold = models[name]["threshold"]
            result = classic_models.evaluate(labels, scores, threshold)
            #FPR liczony tylko na ruchu normalnym hosta IoT: jak często legalny heartbeat wygląda na atak
            iot_normal = (test_flows["src_ip"] == IOT_IP).to_numpy() & (labels == 0)
            fpr_iot = float(np.mean(scores[iot_normal] > threshold)) if iot_normal.any() else float("nan")
            metric_rows.append({
                "scenario": scenario, "test": test_name, "model": name,
                "flows": len(test_flows), "attack_share": round(float(labels.mean()), 3),
                "roc_auc": round(result["roc_auc"], 3),
                "pr_auc": round(result["pr_auc"], 3), "precision": round(result["precision"], 3),
                "recall": round(result["recall"], 3), "f1": round(result["f1"], 3), "fpr": round(result["fpr"], 3),
                "fpr_iot": round(fpr_iot, 3),
                "tp": result["tp"], "fp": result["fp"], "fn": result["fn"], "tn": result["tn"],
                "threshold": threshold, "train_seconds": round(models[name]["train_seconds"], 1),
                "flows_per_second": round(len(test_flows) / max(seconds, 1e-6)),
                #tylko FT: liczba przebiegów treningu (albo dostrajania) i epoka, z której są wagi
                "epochs_run": models[name].get("epochs", {}).get("runs"),
                "best_epoch": models[name].get("epochs", {}).get("best"),
            })
            for attack, recall in classic_models.recall_per_attack(attack_types, scores, threshold).items():
                attack_rows.append({"scenario": scenario, "test": test_name, "model": name,
                                    "attack": attack, "recall": round(recall, 3)})
            decisions = np.where(scores > threshold, "alarm", "brak alarmu")
            for row in classic_models.confusion_rows(attack_types, decisions):
                confusion.append({"scenario": scenario, "test": test_name, "model": name, **row})
            if name == "RF":
                features = flow_features.transform_flows(test_flows, models["preprocessing"])
                classes = classic_models.random_forest_classes(models["RF"]["model"], features, threshold)
                for row in classic_models.confusion_rows(attack_types, classes):
                    confusion.append({"scenario": scenario, "test": test_name, "model": "RF (klasy)", **row})
    return metric_rows, attack_rows, confusion, all_scores


#---------------------------------------------------------------- zapis

#zapis modeli z S1 do models/artifacts/S1/<wariant>/: progi baseline'u, IF i RF (joblib), oba
#przygotowania cech (JSON), wagi FT i progi. run_s2.py wczytuje stąd wagi FT do dostrajania.
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


#format, który czyta app/dashboard.py: przepływy, wyniki modeli, progi i opis biegu
#(scenariusz S1 albo S2, sesja, wariant zbioru źródłowego). Używa go też run_s2.py.
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


#S0 i S1 po kolei dla jednego wariantu zbioru źródłowego; wyniki do results/S0_S1/<wariant>/,
#predykcje S1 dla dashboardu do results/raw/, modele S1 do models/artifacts/.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", nargs="+", required=True,
                        help="zbiór źródłowy: jeden plik (np. sam CIC) albo kilka (np. CIC + GeNIS)")
    parser.add_argument("--sessions", nargs="+", required=True, help="sesje z Mininetu do S1")
    args = parser.parse_args()

    #nazwa wariantu z nazw plików, np. "cic" albo "cic+genis"
    variant = "+".join(os.path.basename(path).replace(".parquet", "") for path in args.source)
    full_source = load_source(args.source)
    source = usable(full_source)
    sessions = {}  #nazwa sesji -> (przepływy testowe, pełna tabela sesji)
    for path in args.sessions:
        full = load_session(path)
        sessions[os.path.basename(path).replace(".parquet", "")] = (usable(full), full)

    print("\n=== S0: trening i test na zbiorze źródłowym ===")
    training, test = split_in_time(source, TRAINING_SHARE_S0)
    models = train_all(training, full_source)
    #test S0 osobno dla każdego źródła, żeby oba warianty dało się porównać na tym samym teście CIC
    test_sets = {}
    for name in sorted(test["source"].unique()):
        test_sets[f"{name}_test"] = (test[test["source"] == name].reset_index(drop=True), full_source)
    s0_metrics, s0_attacks, s0_confusion, _ = evaluate_all("S0", models, test_sets)

    print("\n=== S1: trening na całym zbiorze źródłowym, test na Mininecie ===")
    models = train_all(source, full_source)  #modele uczone od nowa, tym razem na całym źródle (bez podziału 70/30)
    s1_metrics, s1_attacks, s1_confusion, s1_scores = evaluate_all("S1", models, sessions)
    save_s1_models(models, os.path.join(HERE, "artifacts", "S1", variant))
    for session, (flows, _) in sessions.items():
        save_dashboard_predictions(flows, s1_scores[session], models,
                                   os.path.join(RESULTS, "raw", f"S1_{variant}_{session}"), session, variant)

    folder = os.path.join(RESULTS, "S0_S1", variant)
    os.makedirs(folder, exist_ok=True)
    metrics = pd.DataFrame(s0_metrics + s1_metrics)
    metrics.insert(0, "variant", variant)
    metrics.to_csv(os.path.join(folder, "metrics.csv"), index=False)
    pd.DataFrame(s0_attacks + s1_attacks).to_csv(os.path.join(folder, "recall_per_attack.csv"), index=False)
    pd.DataFrame(s0_confusion + s1_confusion).to_csv(os.path.join(folder, "confusion.csv"), index=False)
    print(f"\nFlowTransformer w S1: {models['FT']['epochs']['runs']} przebiegów, "
          f"wagi z epoki {models['FT']['epochs']['best']}")
    print(metrics[["scenario", "test", "model", "attack_share", "recall", "fpr", "fpr_iot", "roc_auc", "f1",
                   "train_seconds", "flows_per_second"]].to_string(index=False))


if __name__ == "__main__":
    main()
