#!/usr/bin/env python3
"""Baseline: proste progi na cechach kontekstu hosta, bez uczenia maszynowego.

Punkt odniesienia dla modeli ML. Alarm, gdy host ma w 60 s dużo przepływów (flood, wolny DoS),
dużo celów albo portów (skan) albo bardzo regularne połączenia do jednego celu (beacon).
Progi z ruchu normalnego treningu (99. percentyl, dla regularności 1.). Wynik = największy stosunek
cecha / próg (> 1, gdy któraś cecha przekracza swój próg); próg alarmu na tym wyniku jest wybierany
jak dla innych modeli, na walidacji przy 1% FPR.
"""
import numpy as np

NORMAL_QUANTILE = 0.99
HIGH_IS_SUSPICIOUS = ["host_flows_60s", "host_destinations_60s", "host_ports_60s"]
MIN_GAP_CV = 1e-3  #dolna granica progu regularności (gdyby ruch normalny był prawie idealnie regularny)


#przepływy, dla których regularność ma sens: 0 < CV < 1 (CV = 1 to brak oceny; CV = 0 to wybuch,
#ale też idealnie równe odstępy - taki przepływ dostaje wynik 0; w sprawdzonych
#nagraniach z 13.11, M0-M3, nie wystąpił).
def assessed(cv):
    return (cv > 0) & (cv < 1)


#progi z ruchu normalnego zbioru treningowego (potrzebne kolumny: cechy kontekstu i label).
def fit_baseline(training_flows):
    normal = training_flows[training_flows["label"] == 0]
    limits = {}
    for name in HIGH_IS_SUSPICIOUS:
        limits[name] = max(float(np.quantile(normal[name], NORMAL_QUANTILE)), 1.0)
    cv = normal["host_dst_gap_cv"].to_numpy()
    cv = cv[assessed(cv)]
    limits["host_dst_gap_cv"] = max(float(np.quantile(cv, 1 - NORMAL_QUANTILE)), MIN_GAP_CV) if len(cv) else MIN_GAP_CV
    return limits


#wynik = największy stosunek cechy do progu (dla regularności: próg / cecha, tylko dla 0 < CV < 1).
def baseline_scores(flows, limits):
    scores = np.zeros(len(flows))
    for name in HIGH_IS_SUSPICIOUS:
        scores = np.maximum(scores, flows[name].to_numpy() / limits[name])
    cv = flows["host_dst_gap_cv"].to_numpy()
    regular = np.where(assessed(cv), limits["host_dst_gap_cv"] / np.where(assessed(cv), cv, 1.0), 0.0)
    return np.maximum(scores, regular)
