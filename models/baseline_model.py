#!/usr/bin/env python3
"""Prosty baseline progowy, bez uczenia maszynowego.

Punkt odniesienia dla modeli ML (Arp i in., USENIX Security 2022): jeśli model nie wygrywa
z kilkoma progami, to jego wynik niewiele znaczy. Baseline patrzy tylko na cechy kontekstu hosta
(features/window_features.py):
  - dużo przepływów w 60 s          (flood, wolny DoS),
  - dużo różnych celów albo portów   (skan portów),
  - bardzo regularne połączenia do jednego celu (beaconing C2).

Progi biorę z ruchu normalnego zbioru treningowego: wartość, której normalny ruch przekracza
tylko w 1% przypadków (dla regularności odwrotnie: 1% najbardziej regularnego ruchu normalnego).
Wynik przepływu = największy stosunek „cecha / próg”, więc wynik > 1 znaczy, że któraś reguła
się przekroczyła. Dzięki temu baseline ma wynik liczbowy jak inne modele (próg przy ok. 1% FPR).
"""
import numpy as np

NORMAL_QUANTILE = 0.99
HIGH_IS_SUSPICIOUS = ["host_flows_60s", "host_destinations_60s", "host_ports_60s"]
MIN_GAP_CV = 1e-3  # zabezpieczenie przed dzieleniem przez 0 przy idealnie równych odstępach


# Progi z ruchu normalnego zbioru treningowego (potrzebne kolumny: cechy kontekstu i label).
def fit_baseline(training_flows):
    normal = training_flows[training_flows["label"] == 0]
    limits = {}
    for name in HIGH_IS_SUSPICIOUS:
        limits[name] = max(float(np.quantile(normal[name], NORMAL_QUANTILE)), 1.0)
    limits["host_dst_gap_cv"] = max(float(np.quantile(normal["host_dst_gap_cv"], 1 - NORMAL_QUANTILE)), MIN_GAP_CV)
    return limits


# Wynik = największy stosunek cechy do progu (dla regularności: próg / cecha).
def baseline_scores(flows, limits):
    scores = np.zeros(len(flows))
    for name in HIGH_IS_SUSPICIOUS:
        scores = np.maximum(scores, flows[name].to_numpy() / limits[name])
    regular = limits["host_dst_gap_cv"] / np.maximum(flows["host_dst_gap_cv"].to_numpy(), MIN_GAP_CV)
    return np.maximum(scores, regular)
