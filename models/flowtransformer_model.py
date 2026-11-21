#!/usr/bin/env python3
"""FlowTransformer w naszych scenariuszach (S0, S1, S2).

Z kodu autorów (models/FlowTransformer, AGPL-3.0, pochodzenie w ZRODLO.md) biorę samą architekturę:
RecordLevelEmbed, 2 bloki enkodera z 2 głowicami, decyzja z ostatniego przepływu, Dense 128 i sigmoid.
Przygotowanie danych, okna i trening są nasze, bo trenujemy na zbiorze publicznym, a testujemy i
dostrajamy na Mininecie. Okno = 8 ostatnich zakończonych przepływów tego samego hosta (brakujące = zera).
Oznaczenia: [AUTORZY] - kod autorów, [WG AUTORÓW] - napisane przeze mnie wiernie jak u autorów,
[MOJE] - napisane przeze mnie inaczej niż u autorów, z powodem.
"""
import os
import sys

import numpy as np

#[AUTORZY] Kod FlowTransformera leży obok tego pliku, w folderze FlowTransformer (oryginał z jedną
#zmianą zgodności z Keras 3, opisaną w ZRODLO.md).
FLOWTRANSFORMER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "FlowTransformer")
sys.path.insert(0, FLOWTRANSFORMER_DIR)
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "features"))

from window_features import window_rows  #noqa: E402

import keras  #noqa: E402
from framework.enumerations import CategoricalFormat  #noqa: E402
from framework.flow_transformer import FlowTransformer  #noqa: E402
from framework.flow_transformer_parameters import FlowTransformerParameters  #noqa: E402
from framework.model_input_specification import ModelInputSpecification  #noqa: E402
from implementations.classification_heads import LastTokenClassificationHead  #noqa: E402
from implementations.input_encodings import RecordLevelEmbed  #noqa: E402
from implementations.transformers.basic_transformers import BasicTransformer  #noqa: E402


#---------------------------------------------------------------- ustawienia

#[WG AUTORÓW] wartości jak w main.py autorów (klocki RecordLevelEmbed i LastToken też są w main.py,
#ale na listach do wyboru; main.py domyślnie buduje model z NoInputEncoder):
WINDOW_SIZE = 8              #liczba przepływów w oknie (main.py: window_size=8)
TRANSFORMER_LAYERS = 2       #liczba bloków enkodera (autorzy: płytki enkoder 2 bloki)
TRANSFORMER_HEADS = 2        #liczba głowic uwagi (autorzy: 2 głowice)
TRANSFORMER_INNER_SIZE = 128  #rozmiar warstwy wewnętrznej bloku (autorzy: FF128)
MLP_SIZE = 128               #warstwa gęsta przed wyjściem (main.py: mlp_layer_sizes=[128])
DROPOUT = 0.1                #(main.py: mlp_dropout=0.1)

#[WG AUTORÓW] rozmiar wektora przepływu po RecordLevelEmbed (main.py: RecordLevelEmbed(64, project=True)).
#kod autorów ostrzega tylko, gdy warstwa wewnętrzna bloku (128) jest mniejsza od wejścia; bez strojenia.
EMBED_DIMENSION = 64

#---------------------------------------------------------------- okna przepływów

#[MOJE] Buduje okna: dla każdego przepływu z rows ostatnie 8 przepływów TEGO SAMEGO hosta źródłowego.
#(Autorzy brali 8 kolejnych wierszy pliku bez względu na host; okno per host to nasze założenie:
#model widzi historię jednego hosta, np. kolejne próby logowania tego samego atakującego.
#etykieta okna = etykieta ostatniego przepływu, jak u autorów.)
#
#flows     - PEŁNA tabela przepływów z indeksem 0..n-1 (src_ip, bidirectional_first_seen_ms,
#            bidirectional_last_seen_ms, label; recording, jeśli jest); z niej pochodzi historia okna,
#rows      - numery wierszy, dla których powstają okna (np. próbka treningowa albo sesja testowa),
#transform - funkcja tabela -> cechy (transform_flows z przygotowaniem FT); liczy cechy tylko
#            przepływów, które trafiają do jakiegoś okna.
#zwraca (okna, etykiety) w kolejności rows; okna mają kształt (len(rows), 8, liczba cech).
def build_windows(flows, rows, transform):
    rows = np.asarray(rows)
    history = window_rows(flows, rows, WINDOW_SIZE)  #(len(rows), 8), -1 = brak przepływu
    needed = np.unique(history[history >= 0])
    features = transform(flows.iloc[needed])
    windows = features[np.searchsorted(needed, np.clip(history, 0, None))]
    windows[history < 0] = 0.0  #gdy historii jest mniej niż 8 przepływów, początek okna to zera
    labels = flows["label"].to_numpy()[rows].astype("float32")
    return windows, labels


#[MOJE] dopasowanie danych do modelu autorów: ich model ma osobne wejście dla każdej cechy,
#więc dzielę okna na kawałki po cechach.
#
#cecha liczbowa ma 1 kolumnę; cecha kategoryczna tyle kolumn, ile ma poziomów one-hot.
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


#---------------------------------------------------------------- model

#[AUTORZY] klasa ModelInputSpecification; [MOJE] wypełnienie jej z naszego przygotowania danych.
def model_input_specification(preprocessing):
    numeric_names = list(preprocessing["numeric"].keys())
    categorical_names = list(preprocessing["categorical"].keys())
    levels = []
    for name in categorical_names:
        levels.append(len(preprocessing["categorical"][name]) + 1)  #+1 na "nieznana"
    return ModelInputSpecification(numeric_names + categorical_names, len(numeric_names), levels,
                                   CategoricalFormat.OneHot)


#[AUTORZY] model składa FlowTransformer.build_model z klocków autorów (RecordLevelEmbed,
#basicTransformer, LastTokenClassificationHead, Dense 128, wyjście sigmoid); te klocki są w main.py,
#ale main.py domyślnie używa NoInputEncoder. [MOJE] kompilacja: optymalizator Adam jak u autorów, metryka PR-AUC
#(nasza metryka główna) zamiast metryk autorów.
def build_model(preprocessing):
    flow_transformer = FlowTransformer(
        pre_processing=None,
        input_encoding=RecordLevelEmbed(EMBED_DIMENSION, project=True),
        sequential_model=BasicTransformer(n_layers=TRANSFORMER_LAYERS, internal_size=TRANSFORMER_INNER_SIZE,
                                          n_heads=TRANSFORMER_HEADS, dropout_rate=DROPOUT),
        classification_head=LastTokenClassificationHead(),
        params=FlowTransformerParameters(window_size=WINDOW_SIZE, mlp_layer_sizes=[MLP_SIZE], mlp_dropout=DROPOUT),
    )
    #build_model autorów sprawdza tylko, czy dane zostały wczytane, i czyta opis wejść.
    flow_transformer.X = "dane przygotowane poza FlowTransformerem"
    flow_transformer.model_input_spec = model_input_specification(preprocessing)
    model = flow_transformer.build_model()
    model.compile(optimizer=keras.optimizers.Adam(learning_rate=1e-3),
                  loss="binary_crossentropy",
                  metrics=[keras.metrics.AUC(curve="PR", name="pr_auc")])
    return model
