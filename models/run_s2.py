#!/usr/bin/env python3
r"""Scenariusz S2: adaptacja na sesji M0, test na sesjach M1-M6.

M0 (bez Z1) dzielona w czasie: 70% do adaptacji, 30% walidacja (progi, zatrzymanie FT po 3 epokach
bez poprawy, najwyżej 20 epok).
Baseline bierze progi z M0, IF i RF uczą się od nowa na próbce źródła i M0. RF dostaje wagi: M0 waży
razem tyle co źródło, a potem każda klasa razem tyle samo (w klasie M0 zostaje ważniejsze); IF bez wag.
FT dostraja wagi z S1 z 10 razy mniejszym krokiem. Wyniki do results/S2/<wariant>/ i results/raw/.

    /root/venvs/ft/bin/python models/run_s2.py --source data/flows/cic.parquet \
        --adaptation data/flows/M0.parquet \
        --sessions data/flows/M1.parquet data/flows/M2.parquet
"""
import argparse
import os

import pandas as pd

import run_experiments as rx
from run_experiments import keras, flow_features, ftm

ADAPTATION_SHARE = 0.7   #część M0 (w czasie) do adaptacji; reszta to walidacja
FINE_TUNE_LEARNING_RATE = 1e-4
FINE_TUNE_EPOCHS = 20  #jak MAX_EPOCHS w S1; przy 10 najlepsza epoka była zawsze ostatnia


#FT z S1 dostrajany na M0; przygotowanie cech zostaje to samo co w S1
def fine_tune_flowtransformer(artifacts, adaptation, validation, m0_full):
    keras.utils.set_random_seed(rx.RANDOM_SEED)
    preprocessing = flow_features.load_preprocessing(os.path.join(artifacts, "preprocessing_ft.json"))
    spec = ftm.model_input_specification(preprocessing)
    #ta sama architektura co w S1, wagi z pliku, potem ponowna kompilacja z 10x mniejszym krokiem uczenia,
    #żeby dostrojenie tylko lekko poprawiło model, a nie nauczyło go od nowa
    model = ftm.build_model(preprocessing)
    model.load_weights(os.path.join(artifacts, "flowtransformer.weights.h5"))
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=FINE_TUNE_LEARNING_RATE),
                  loss="binary_crossentropy", metrics=[keras.metrics.AUC(curve="PR", name="pr_auc")])

    #okna wszystkich przepływów części adaptacyjnej M0 (bez próbkowania - M0 jest małe)
    inputs, labels = rx.flowtransformer_inputs(m0_full, adaptation, preprocessing, spec)
    validation_inputs, validation_labels = rx.flowtransformer_inputs(m0_full, validation, preprocessing, spec)
    threshold, epochs = rx.fit_flowtransformer(model, inputs, labels, validation_inputs, validation_labels,
                                               FINE_TUNE_EPOCHS)
    return model, preprocessing, threshold, epochs


#Wszystkie modele po adaptacji na M0; progi z walidacji M0.
def adapt_all(source, adaptation, validation, artifacts, m0_full):
    #ta sama próbka źródła co w S1 (split_and_sample z tym samym ziarnem) + część adaptacyjna M0;
    #IF bierze z tego tylko ruch normalny, RF wszystko (z wagami niżej), a baseline progi tylko z M0
    #(baseline_training=adaptation)
    _, source_sample, _ = rx.split_and_sample(source)
    training = pd.concat([source_sample, adaptation], ignore_index=True)
    print("Adaptacja M0:", adaptation["attack_type"].value_counts().to_dict())
    print("Walidacja M0 (progi):", validation["attack_type"].value_counts().to_dict())

    #przygotowanie cech IF i RF z próbki źródła i M0 (w S1 z całej części do uczenia, bez próbkowania)
    preprocessing = flow_features.fit_preprocessing(training)
    #wagi tylko dla RF: M0 waży razem tyle, co cała próbka ze źródła (inaczej ok. 25 tys. przepływów M0
    #zginęłoby wśród ok. 69 tys. przepływów próbki CIC albo 150 tys. CIC + GeNIS; waga M0 ok. 2,8 / 6,0)
    weights = [1.0] * len(source_sample) + [len(source_sample) / len(adaptation)] * len(adaptation)
    models = rx.train_classic(training, flow_features.transform_flows(training, preprocessing), validation,
                              flow_features.transform_flows(validation, preprocessing),
                              baseline_training=adaptation, sample_weight=weights)
    models["preprocessing"] = preprocessing

    #czas FT = sam fit (jak dla IF i RF), bez wczytania modelu, budowy okien i wyboru progu
    model, ft_preprocessing, threshold, epochs = fine_tune_flowtransformer(artifacts, adaptation, validation, m0_full)
    models["FT"] = {"model": model, "threshold": threshold, "train_seconds": epochs["fit_seconds"],
                    "preprocessing": ft_preprocessing, "epochs": epochs}
    return models


#S2 dla jednego wariantu: wczytanie źródła i sesji, podział M0 w czasie (70% adaptacja, 30% walidacja),
#adaptacja wszystkich modeli, test na M1-M6, wyniki do results/S2/<wariant>/.
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", nargs="+", required=True, help="ten sam zbiór źródłowy co w S1")
    parser.add_argument("--adaptation", required=True, help="sesja adaptacyjna M0")
    parser.add_argument("--sessions", nargs="+", required=True, help="sesje testowe M1-M6")
    args = parser.parse_args()

    variant = "+".join(os.path.basename(path).replace(".parquet", "") for path in args.source)
    artifacts = os.path.join(rx.HERE, "artifacts", "S1", variant)
    source = rx.usable(rx.load_source(args.source))
    m0_full = rx.load_session(args.adaptation)
    adaptation, validation = rx.split_in_time(rx.usable(m0_full), ADAPTATION_SHARE)
    sessions = {}  #nazwa sesji -> (przepływy testowe, pełna tabela sesji)
    for path in args.sessions:
        full = rx.load_session(path)
        sessions[os.path.basename(path).replace(".parquet", "")] = (rx.usable(full), full)

    print("\n=== S2: adaptacja na M0, test na sesjach z Mininetu ===")
    models = adapt_all(source, adaptation, validation, artifacts, m0_full)
    metrics, attacks, confusion, scores = rx.evaluate_all("S2", models, sessions)
    #predykcje S2 w formacie dashboardu (przełącznik "scenariusz" w app/dashboard.py)
    for session, (flows, _) in sessions.items():
        folder = os.path.join(rx.RESULTS, "raw", f"S2_{variant}_{session}")
        rx.save_dashboard_predictions(flows, scores[session], models, folder, session, variant, "S2")

    folder = os.path.join(rx.RESULTS, "S2", variant)
    os.makedirs(folder, exist_ok=True)
    metrics = pd.DataFrame(metrics)
    metrics.insert(0, "variant", variant)
    metrics.to_csv(os.path.join(folder, "metrics.csv"), index=False)
    pd.DataFrame(attacks).to_csv(os.path.join(folder, "recall_per_attack.csv"), index=False)
    pd.DataFrame(confusion).to_csv(os.path.join(folder, "confusion.csv"), index=False)
    print(f"\nDostrajanie FlowTransformera: {models['FT']['epochs']['runs']} przebiegów, "
          f"wagi z epoki {models['FT']['epochs']['best']}")
    columns = ["test", "model", "attack_share", "recall", "fpr", "fpr_iot", "roc_auc", "f1"]
    print(metrics[columns].to_string(index=False))


if __name__ == "__main__":
    main()
