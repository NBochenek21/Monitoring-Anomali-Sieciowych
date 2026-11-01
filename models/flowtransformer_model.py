#!/usr/bin/env python3
"""FlowTransformer w naszych scenariuszach (S0, S1, S2).

Z oryginalnego kodu FlowTransformera (models/FlowTransformer, Manocchio i in. 2024, licencja AGPL-3.0)
biorę tylko architekturę modelu, czyli te same klocki co w artykule:
  - RecordLevelEmbed      - każdy przepływ (rekord) zamieniany jest na jeden wektor,
  - BasicTransformer      - bloki enkodera Transformera (2 bloki, 2 głowice),
  - LastTokenClassificationHead - decyzję podejmuje wektor ostatniego przepływu w oknie,
  - warstwa Dense(128) i wyjście sigmoid (prawdopodobieństwo ataku).

Przygotowanie danych, okna i trening piszę sam, bo oryginalna pętla treningowa ocenia model tylko
na końcówce tego samego zbioru i przy każdym wczytaniu danych od nowa dopasowuje przygotowanie.
My trenujemy na zbiorze publicznym, a testujemy i dostrajamy na danych z Mininetu, więc:
  1. przygotowanie danych dopasowuję RAZ na zbiorze treningowym i zapisuję do pliku JSON,
  2. to samo przygotowanie stosuję potem do każdego innego zbioru (np. z Mininetu),
  3. wagi modelu z S1 zapisuję do pliku, żeby w S2 dostroić je na M0.

Pochodzenie kodu w tym pliku (oznaczenia przy każdej części):
  [AUTORZY]        - wywołanie kodu autorów z folderu models/FlowTransformer (bez zmian, opis w ZRODLO.md),
  [WG AUTORÓW]     - napisane przeze mnie, ale wiernie odtwarza sposób autorów (wzór, wartości),
  [NASZE]          - napisane przeze mnie, inaczej niż u autorów; przy każdym jest powód.

Okno: 8 kolejnych przepływów tego samego hosta źródłowego (posortowanych po czasie startu).
Etykieta okna = etykieta jego ostatniego przepływu. Pierwsze przepływy hosta, które nie mają
jeszcze 7 poprzedników, dostają okno uzupełnione zerami na początku, więc każdy przepływ ma
swoją predykcję.
"""
import os
import sys

import numpy as np

# [AUTORZY] Kod FlowTransformera leży obok tego pliku, w folderze FlowTransformer (oryginał, bez zmian).
FLOWTRANSFORMER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FlowTransformer")
sys.path.insert(0, FLOWTRANSFORMER_DIR)

import keras  # noqa: E402
from framework.enumerations import CategoricalFormat  # noqa: E402
from framework.flow_transformer import FlowTransformer  # noqa: E402
from framework.flow_transformer_parameters import FlowTransformerParameters  # noqa: E402
from framework.model_input_specification import ModelInputSpecification  # noqa: E402
from implementations.classification_heads import LastTokenClassificationHead  # noqa: E402
from implementations.input_encodings import RecordLevelEmbed  # noqa: E402
from implementations.transformers.basic_transformers import BasicTransformer  # noqa: E402


# ---------------------------------------------------------------- ustawienia

# [WG AUTORÓW] wartości jak w main.py autorów i najlepszej konfiguracji z artykułu:
WINDOW_SIZE = 8              # liczba przepływów w oknie (main.py: window_size=8)
TRANSFORMER_LAYERS = 2       # liczba bloków enkodera (artykuł: płytki enkoder 2 bloki)
TRANSFORMER_HEADS = 2        # liczba głowic uwagi (artykuł: 2 głowice)
TRANSFORMER_INNER_SIZE = 128  # rozmiar warstwy wewnętrznej bloku (artykuł: FF128)
MLP_SIZE = 128               # warstwa gęsta przed wyjściem (main.py: mlp_layer_sizes=[128])
DROPOUT = 0.1                # (main.py: mlp_dropout=0.1)

# [NASZE] rozmiar wektora przepływu po RecordLevelEmbed. Autorzy zalecają wymiar wewnętrzny
# 1-2 razy większy od wejścia; dobieram go przy strojeniu hiperparametrów, 64 to punkt startowy.
EMBED_DIMENSION = 64

# ---------------------------------------------------------------- okna przepływów

# [NASZE] Buduje okna: dla każdego przepływu ostatnie 8 przepływów TEGO SAMEGO hosta źródłowego.
# (Autorzy brali 8 kolejnych wierszy pliku bez względu na host; okno per host to założenie z planu
# pracy - model widzi historię jednego hosta, np. kolejne próby logowania tego samego atakującego.
# Etykieta okna = etykieta ostatniego przepływu, jak u autorów.)
#
# flows         - tabela przepływów (potrzebne: src_ip, bidirectional_first_seen_ms, label; recording, jeśli jest),
# flow_features - wynik transform_flows dla tych samych wierszy, w tej samej kolejności.
# Zwraca (okna, etykiety, numery wierszy), okna mają kształt (liczba przepływów, 8, liczba cech).
def build_windows(flows, flow_features):
    number_of_flows, number_of_features = flow_features.shape
    windows = np.zeros((number_of_flows, WINDOW_SIZE, number_of_features), dtype="float32")
    labels = np.zeros(number_of_flows, dtype="float32")
    row_numbers = np.zeros(number_of_flows, dtype="int64")

    # Kolejność: host źródłowy, a w nim czas startu przepływu.
    # positions[k] = numer wiersza (0, 1, 2, ...) przepływu, który w tej kolejności jest k-ty.
    # W zbiorach publicznych ten sam adres hosta występuje w kilku nagraniach (różne dni), więc tam
    # „host” = para (nagranie, adres): okno nie łączy przepływów z różnych nagrań.
    numbered = flows.reset_index(drop=True)
    host_keys = numbered["src_ip"].astype(str)
    if "recording" in numbered.columns:
        host_keys = numbered["recording"].astype(str) + "/" + host_keys
    numbered = numbered.assign(host_key=host_keys)
    positions = numbered.sort_values(["host_key", "bidirectional_first_seen_ms"], kind="stable").index.to_numpy()
    hosts = numbered["host_key"].to_numpy()[positions]
    flow_labels = numbered["label"].to_numpy()[positions]

    window_number = 0
    host_start = 0
    while host_start < number_of_flows:
        # Wszystkie przepływy jednego hosta leżą obok siebie (posortowane).
        host_end = host_start
        while host_end < number_of_flows and hosts[host_end] == hosts[host_start]:
            host_end += 1

        for current in range(host_start, host_end):
            first = max(host_start, current - WINDOW_SIZE + 1)
            history = flow_features[positions[first:current + 1]]
            # Gdy historii jest mniej niż 8 przepływów, początek okna zostaje wypełniony zerami.
            windows[window_number, WINDOW_SIZE - len(history):] = history
            labels[window_number] = flow_labels[current]
            row_numbers[window_number] = positions[current]
            window_number += 1
        host_start = host_end

    return windows, labels, row_numbers


# [NASZE] dopasowanie danych do modelu autorów: ich model ma osobne wejście dla każdej cechy,
# więc dzielę okna na kawałki po cechach.
#
# Cecha liczbowa ma 1 kolumnę; cecha kategoryczna tyle kolumn, ile ma poziomów one-hot.
def windows_to_model_inputs(windows, model_input_spec):
    inputs = []
    column = 0
    for _ in model_input_spec.numeric_feature_names:
        inputs.append(windows[:, :, column:column + 1])
        column += 1
    for levels in model_input_spec.levels_per_categorical_feature:
        inputs.append(windows[:, :, column:column + levels])
        column += levels
    return inputs


# ---------------------------------------------------------------- model

# [AUTORZY] klasa ModelInputSpecification; [NASZE] wypełnienie jej z naszego przygotowania danych.
def model_input_specification(preprocessing):
    numeric_names = list(preprocessing["numeric"].keys())
    categorical_names = list(preprocessing["categorical"].keys())
    levels = []
    for name in categorical_names:
        levels.append(len(preprocessing["categorical"][name]) + 1)  # +1 na „nieznana”
    return ModelInputSpecification(numeric_names + categorical_names, len(numeric_names), levels,
                                   CategoricalFormat.OneHot)


# [AUTORZY] model składa FlowTransformer.build_model z klocków autorów (RecordLevelEmbed,
# BasicTransformer, LastTokenClassificationHead, Dense 128, wyjście sigmoid), w konfiguracji
# zalecanej w artykule. [NASZE] kompilacja: optymalizator Adam jak u autorów, metryka PR-AUC
# (nasza metryka główna) zamiast metryk autorów.
def build_model(preprocessing):
    flow_transformer = FlowTransformer(
        pre_processing=None,
        input_encoding=RecordLevelEmbed(EMBED_DIMENSION, project=True),
        sequential_model=BasicTransformer(n_layers=TRANSFORMER_LAYERS, internal_size=TRANSFORMER_INNER_SIZE,
                                          n_heads=TRANSFORMER_HEADS, dropout_rate=DROPOUT),
        classification_head=LastTokenClassificationHead(),
        params=FlowTransformerParameters(window_size=WINDOW_SIZE, mlp_layer_sizes=[MLP_SIZE], mlp_dropout=DROPOUT),
    )
    # build_model autorów sprawdza tylko, czy dane zostały wczytane, i czyta opis wejść.
    flow_transformer.X = "dane przygotowane poza FlowTransformerem"
    flow_transformer.model_input_spec = model_input_specification(preprocessing)
    model = flow_transformer.build_model()
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=1e-3),
                  loss="binary_crossentropy",
                  metrics=[keras.metrics.AUC(curve="PR", name="pr_auc")])
    return model
