#!/usr/bin/env python3
"""Wspólne przygotowanie cech dla wszystkich modeli.

Cechy liczbowe skalowane logarytmicznie jak w kodzie FlowTransformera, port i protokół jako one-hot
(32 najczęstsze wartości + "nieznana"). Przygotowanie uczy się tylko na treningu, zapisuje do JSON
i potem bez zmian stosuje do każdego innego zbioru (np. z Mininetu).
Oznaczenia: [WG AUTORÓW] - jak u autorów FlowTransformera, [MOJE] - inaczej niż u autorów, z powodem.
"""
import json

import numpy as np
import pandas as pd

#[WG AUTORÓW] ile najczęstszych wartości kategorii zapamiętać (main.py autorów: n_categorical_levels=32).
CATEGORICAL_LEVELS = 32

#[MOJE] cechy kategoryczne dla przepływów NFStream (autorzy mieli inne nazwy kolumn, z NetFlow).
CATEGORICAL_FEATURES = ["protocol", "dst_port"]

#[MOJE] Kolumny, które NIE są cechami modelu: identyfikatory, czasy (służą tylko do sortowania),
#etykiety i kolumny pomocnicze z ekstrakcji. Wszystkie pozostałe kolumny liczbowe są cechami.
#(Autorzy też usuwali adresy IP.)
#  expiration_id - sposób zakończenia przepływu przez nasze narzędzie (FIN/RST, idle, active), czyli
#                  artefakt ekstrakcji, a nie ruchu; mógłby być skrótem dla modelu,
#  *_payload_bytes - tylko do etykiety "attempted" (features/label_flows.py),
#  row             - numer wiersza w pełnej tabeli (do okien FT, models/run_experiments.py).
NOT_FEATURES = [
    "id", "src_ip", "dst_ip", "src_port",
    "bidirectional_first_seen_ms", "bidirectional_last_seen_ms",
    "src2dst_first_seen_ms", "src2dst_last_seen_ms",
    "dst2src_first_seen_ms", "dst2src_last_seen_ms",
    "expiration_id", "src2dst_payload_bytes", "dst2src_payload_bytes",
    "label", "attack_type", "source", "recording", "row",
]


#lista cech liczbowych: kolumny liczbowe, które nie są identyfikatorem, czasem ani etykietą.
def numeric_feature_names(flows):
    names = []
    for column in flows.columns:
        if column in NOT_FEATURES or column in CATEGORICAL_FEATURES:
            continue
        if pd.api.types.is_numeric_dtype(flows[column]):
            names.append(column)
    return names


#[WG AUTORÓW] wzór jak StandardPreProcessing, [MOJE] zapis do JSON.
#
#uczy przygotowania danych WYŁĄCZNIE na zbiorze treningowym.
#dla cech liczbowych zapamiętuje minimum i zakres (jak StandardPreProcessing autorów).
#dla cech kategorycznych zapamiętuje 32 najczęstsze wartości.
#zwraca słownik, który da się zapisać do pliku JSON.
def fit_preprocessing(training_flows):
    preprocessing = {"numeric": {}, "categorical": {}}

    for name in numeric_feature_names(training_flows):
        values = training_flows[name].astype("float64").to_numpy()
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)  #tak samo jak w transform_flows
        minimum = float(np.min(values))
        value_range = float(np.max(values) - minimum)
        preprocessing["numeric"][name] = {"min": minimum, "range": value_range}

    for name in CATEGORICAL_FEATURES:
        counts = training_flows[name].value_counts()
        most_common = []
        for value in counts.index[:CATEGORICAL_LEVELS]:
            most_common.append(int(value))
        preprocessing["categorical"][name] = most_common

    return preprocessing


#[WG AUTORÓW] skalowanie logarytmiczne: log(x - min + 1) / log(zakres + 1).
#[MOJE] przycięcie wartości poniżej minimum. Autorzy też dopasowywali minimum tylko na treningu, ale nie
#przycinali; ich test pochodził z tego samego zbioru, więc rzadko wychodził poza zakres.
#
#wartości z innego zbioru mogą wyjść poza zakres treningowy. Te poniżej minimum przycinam
#do minimum (logarytm z liczby ujemnej nie istnieje); te powyżej zakresu zostają większe od 1.
def transform_numeric(values, minimum, value_range):
    if value_range == 0:
        return np.zeros(len(values), dtype="float32")
    shifted = np.clip(values - minimum, 0, None)
    return (np.log(shifted + 1) / np.log(value_range + 1)).astype("float32")


#[MOJE] kodowanie one-hot o STAŁEJ długości: 1 kolumna na "nieznana" + po 1 na każdą zapamiętaną wartość.
#(Autorzy używali pd.get_dummies, którego liczba kolumn zależy od danych - przy innym zbiorze
#model dostałby wejście innej szerokości.)
#
#wartość niewidziana w treningu (np. nowy port w Mininecie) trafia do kolumny "nieznana".
#(W kodzie autorów taka wartość dostawała kod najczęstszej wartości - tu to poprawiam.)
def transform_categorical(values, known_values):
    one_hot = np.zeros((len(values), len(known_values) + 1), dtype="float32")
    position_of_value = {}
    for position, value in enumerate(known_values):
        position_of_value[value] = position + 1  #pozycja 0 = "nieznana"
    for row, value in enumerate(values):
        one_hot[row, position_of_value.get(int(value), 0)] = 1.0
    return one_hot


#[MOJE] Zamienia tabelę przepływów na tablicę cech: jeden wiersz = jeden przepływ.
#
#kolejność kolumn jest zawsze taka sama: najpierw cechy liczbowe (w kolejności z preprocessing),
#potem kolumny one-hot kolejnych cech kategorycznych.
def transform_flows(flows, preprocessing):
    columns = []
    for name, scaling in preprocessing["numeric"].items():
        values = flows[name].astype("float64").to_numpy()
        #braki i nieskończoności (np. odchylenie przy przepływie z 1 pakietem) zamieniam na 0
        values = np.nan_to_num(values, nan=0.0, posinf=0.0, neginf=0.0)
        columns.append(transform_numeric(values, scaling["min"], scaling["range"]).reshape(-1, 1))
    for name, known_values in preprocessing["categorical"].items():
        columns.append(transform_categorical(flows[name].to_numpy(), known_values))
    return np.concatenate(columns, axis=1)


#[MOJE] zapis i odczyt przygotowania danych (u autorów nie istniał; potrzebny do S1 i S2).
def save_preprocessing(preprocessing, path):
    with open(path, "w") as file:
        json.dump(preprocessing, file, indent=2)


#odczyt zapisanego przygotowania (w S2: to samo przygotowanie cech FT co w S1).
def load_preprocessing(path):
    with open(path) as file:
        return json.load(file)
