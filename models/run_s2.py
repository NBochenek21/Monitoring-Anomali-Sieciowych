#!/usr/bin/env python3
"""Scenariusz S2: transfer z adaptacją na jednej sesji z Mininetu (M0), test na sesjach M1-M6.

Wejście: modele z S1 (models/artifacts/S1/<wariant>/, zapisuje je run_experiments.py), ten sam zbiór
źródłowy co w S1 i sesja adaptacyjna M0 (bez Z1, więc beaconing zostaje atakiem niewidzianym).

Sesję M0 dzielę w czasie jak w S0: pierwsze 70% przepływów każdej klasy to dane do adaptacji,
ostatnie 30% to walidacja - na niej wyznaczam progi (ok. 1% FPR) i zatrzymuję dostrajanie FT.
Adaptacja (decyzje własne, zgodne z planem pracy):
  baseline - progi z ruchu normalnego M0 zamiast ze źródła,
  IF       - uczony od nowa na ruchu normalnym ze źródła i z M0,
  RF       - uczony od nowa na źródle i M0; M0 waży razem tyle, co cała próbka ze źródła,
  FT       - wagi z S1 dostrajane na M0 z 10 razy mniejszym krokiem uczenia (1e-4 zamiast 1e-3).

Wyniki (ten sam format co S0/S1): results/S2/<wariant>/metrics.csv i recall_per_attack.csv,
a predykcje do odtwarzania w dashboardzie: results/raw/S2_<wariant>_<sesja>/.

    /root/venvs/ft/bin/python models/run_s2.py --source data/flows/cic.parquet \
        --adaptation data/flows/M0.parquet --sessions data/flows/M1.parquet data/flows/M2.parquet
"""
import argparse
import os
import time

import pandas as pd

import run_experiments as rx
from run_experiments import keras, flow_features, ftm
from window_features import WINDOW_FEATURES

ADAPTATION_SHARE = 0.7   # część M0 (w czasie) do adaptacji; reszta to walidacja
FINE_TUNE_LEARNING_RATE = 1e-4
FINE_TUNE_EPOCHS = 10


# Wagi FT z S1 + dostrojenie na M0. Przygotowanie danych (preprocessing) zostaje z S1.
def fine_tune_flowtransformer(artifacts, adaptation, validation):
    keras.utils.set_random_seed(rx.RANDOM_SEED)
    preprocessing = flow_features.load_preprocessing(os.path.join(artifacts, "preprocessing_ft.json"))
    spec = ftm.model_input_specification(preprocessing)
    # ta sama architektura co w S1, wagi z pliku, potem ponowna kompilacja z 10x mniejszym krokiem uczenia,
    # żeby dostrojenie tylko lekko poprawiło model, a nie nauczyło go od nowa
    model = ftm.build_model(preprocessing)
    model.load_weights(os.path.join(artifacts, "flowtransformer.weights.h5"))
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=FINE_TUNE_LEARNING_RATE),
                  loss="binary_crossentropy", metrics=[keras.metrics.AUC(curve="PR", name="pr_auc")])

    # wszystkie okna części adaptacyjnej M0 (bez próbkowania - M0 jest małe)
    windows, labels, _ = rx.flowtransformer_windows(adaptation.drop(columns=WINDOW_FEATURES), preprocessing)
    validation_windows, validation_labels, _ = rx.flowtransformer_windows(validation.drop(columns=WINDOW_FEATURES),
                                                                          preprocessing)
    threshold, epochs = rx.fit_flowtransformer(model, ftm.windows_to_model_inputs(windows, spec), labels,
                                               ftm.windows_to_model_inputs(validation_windows, spec),
                                               validation_labels, FINE_TUNE_EPOCHS)
    return model, preprocessing, threshold, epochs


# Wszystkie modele po adaptacji na M0; progi z walidacji M0.
def adapt_all(source, adaptation, validation, artifacts):
    # ta sama próbka źródła co w S1 + część adaptacyjna M0; IF bierze z tego tylko ruch normalny,
    # RF wszystko (z wagami niżej), a baseline progi tylko z M0 (baseline_training=adaptation)
    source_sample = source[rx.sample_mask(source)].reset_index(drop=True)
    training = pd.concat([source_sample, adaptation], ignore_index=True)
    print("Adaptacja M0:", adaptation["attack_type"].value_counts().to_dict())
    print("Walidacja M0 (progi):", validation["attack_type"].value_counts().to_dict())

    preprocessing = flow_features.fit_preprocessing(training)
    # M0 waży razem tyle, co cała próbka ze źródła (inaczej kilka tysięcy przepływów M0 zginęłoby
    # wśród ok. 100 tys. przepływów źródła)
    weights = [1.0] * len(source_sample) + [len(source_sample) / len(adaptation)] * len(adaptation)
    models = rx.train_classic(training, flow_features.transform_flows(training, preprocessing), validation,
                              flow_features.transform_flows(validation, preprocessing),
                              baseline_training=adaptation, sample_weight=weights)
    models["preprocessing"] = preprocessing

    start = time.time()
    model, ft_preprocessing, threshold, epochs = fine_tune_flowtransformer(artifacts, adaptation, validation)
    models["FT"] = {"model": model, "threshold": threshold, "train_seconds": time.time() - start,
                    "preprocessing": ft_preprocessing, "epochs": epochs}
    return models


# S2 dla jednego wariantu: wczytanie źródła i sesji, podział M0 w czasie (70% adaptacja, 30% walidacja),
# adaptacja wszystkich modeli, test na M1-M6, wyniki do results/S2/<wariant>/.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", nargs="+", required=True, help="ten sam zbiór źródłowy co w S1")
    parser.add_argument("--adaptation", required=True, help="sesja adaptacyjna M0")
    parser.add_argument("--sessions", nargs="+", required=True, help="sesje testowe M1-M6")
    args = parser.parse_args()

    variant = "+".join(os.path.basename(path).replace(".parquet", "") for path in args.source)
    artifacts = os.path.join(rx.HERE, "artifacts", "S1", variant)
    source = rx.load_source(args.source)
    adaptation, validation = rx.split_in_time(rx.load_session(args.adaptation), ADAPTATION_SHARE)
    sessions = {}
    for path in args.sessions:
        sessions[os.path.basename(path).replace(".parquet", "")] = rx.load_session(path)

    print("\n=== S2: adaptacja na M0, test na sesjach z Mininetu ===")
    models = adapt_all(source, adaptation, validation, artifacts)
    metrics, attacks, scores = rx.evaluate_all("S2", models, sessions)
    # predykcje S2 w formacie dashboardu (przełącznik „scenariusz” w app/dashboard.py)
    for session, flows in sessions.items():
        rx.save_dashboard_predictions(flows, scores[session], models,
                                      os.path.join(rx.RESULTS, "raw", f"S2_{variant}_{session}"), session, variant, "S2")

    folder = os.path.join(rx.RESULTS, "S2", variant)
    os.makedirs(folder, exist_ok=True)
    metrics = pd.DataFrame(metrics)
    metrics.insert(0, "variant", variant)
    metrics.to_csv(os.path.join(folder, "metrics.csv"), index=False)
    pd.DataFrame(attacks).to_csv(os.path.join(folder, "recall_per_attack.csv"), index=False)
    print("\nEpoki dostrajania FlowTransformera:", models["FT"]["epochs"])
    print(metrics[["test", "model", "attack_share", "pr_auc", "precision", "recall", "f1", "fpr",
                   "fpr_iot"]].to_string(index=False))


if __name__ == "__main__":
    main()
