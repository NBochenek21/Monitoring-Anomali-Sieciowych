#!/usr/bin/env python3
"""Porównanie modeli na sesjach testowych z Mininetu (M1-M6).

Jednostka = sesja: każda sesja to osobny zbiór testowy, więc wynik modelu to średnia z sesji,
a rozrzut między sesjami pokazuje, na ile wynik jest stabilny.

Miary: tylko takie, które nie zależą od udziału ataków w teście. Recall (TPR) liczy się wyłącznie
na przepływach ataku, a FPR wyłącznie na ruchu normalnym, więc nie zmieniają się z proporcją klas.
W sesjach M1-M6 ataki to 83-90% przepływów (w prawdziwej sieci ruch normalny dominuje), dlatego
precision, F1 i PR-AUC byłyby tu zawyżone i nie trafiają do statystyki (run_experiments.py nadal je
zapisuje w metrics.csv). FPR jako miara operacyjna: Sommer i Paxson 2010 (koszt fałszywych alarmów);
miary dopasowane do niezbalansowania i niskiego FPR: Arp i in. 2022 (P7, P8). Liczę:
  1. średnią i 95% przedział ufności t-Studenta (średnia ± połowa szerokości przedziału) dla recall,
     FPR i FPR na heartbeacie IoT, osobno S1 i S2,
  2. FPR każdego modelu w każdej sesji (do wykresu: widać, czy wynik jest stały między sesjami),
  3. recall każdego ataku (w tym Z1, atak niewidziany): średnia po sesjach (do heatmapy model x atak),
  4. S2 wobec S1 dla każdego modelu (pary: ta sama sesja): średnia różnica FPR i recall oraz w ilu
     sesjach S2 wypadło lepiej (FPR niżej, recall wyżej),
  5. (opcjonalnie, --traffic) realizm generatora ruchu: odstępy między sesjami użytkownika każdego
     hosta (logi traffic_*.jsonl). Dla procesu Poissona odstępy są wykładnicze: współczynnik
     zmienności (CV) ok. 1 i mała statystyka D testu Kołmogorowa-Smirnowa. Kontrast: heartbeat IoT
     (prawie stałe odstępy, CV ok. 0). Generator losuje odstępy z rozkładu wykładniczego, więc ten
     pomiar sprawdza, że ruch w nagraniu zgadza się z projektem i z modelem Poissona dla sesji
     użytkownika (Paxson i Floyd 1995), a nie podobieństwo do ruchu konkretnej prawdziwej firmy.

Wynik: results/stats/<wariant>/*.csv (czyta je dashboard, zakładka „Porównanie”).

    /root/venvs/ft/bin/python stats/summarize.py --variant cic --traffic /root/sessions/M1 /root/sessions/M2
"""
import argparse
import glob
import json
import os

import numpy as np
import pandas as pd
from scipy import stats

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")
METRICS = ["recall", "fpr", "fpr_iot"]  # miary niezależne od udziału ataków w teście (opis wyżej)
USER_SESSIONS = ["web_browse", "dns_lookup", "mail_send", "ssh_work", "file_transfer", "ssh_admin"]


# Średnia i połowa szerokości 95% przedziału ufności t-Studenta (n - 1 stopni swobody).
def mean_with_ci(values):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return float("nan"), float("nan")
    if len(values) < 2:
        return float(values.mean()), float("nan")  # z jednej wartości nie da się policzyć rozrzutu
    # połowa przedziału = t(0,975; n-1) * odchylenie z próby / pierwiastek z n (przy n = 6: t ≈ 2,571)
    half_width = stats.t.ppf(0.975, len(values) - 1) * values.std(ddof=1) / np.sqrt(len(values))
    return float(values.mean()), float(half_width)


# Wiersze S1 (z run_experiments.py) i S2 (z run_s2.py), tylko sesje z Mininetu.
def load_results(variant, name):
    tables = []
    for folder in ("S0_S1", "S2"):
        path = os.path.join(RESULTS, folder, variant, name)
        if os.path.exists(path):
            tables.append(pd.read_csv(path))
    if not tables:
        raise SystemExit(f"Brak wyników dla wariantu {variant} w {RESULTS}")
    results = pd.concat(tables, ignore_index=True)
    return results[results["scenario"].isin(["S1", "S2"])]


# Tabela: scenariusz x model -> średnia ± przedział dla każdej metryki.
def summarize_models(results):
    rows = []
    for (scenario, model), group in results.groupby(["scenario", "model"]):
        row = {"scenario": scenario, "model": model, "sessions": len(group)}
        for metric in METRICS:
            mean, half_width = mean_with_ci(group[metric])
            row[metric] = round(mean, 3)
            row[f"{metric}_ci95"] = round(half_width, 3)
        rows.append(row)
    return pd.DataFrame(rows)


# Recall każdego ataku: średnia po sesjach, dla każdego scenariusza i modelu.
def summarize_attacks(attack_results):
    table = attack_results.groupby(["scenario", "model", "attack"])["recall"].agg(["mean", "count"])
    return table.reset_index().rename(columns={"mean": "recall", "count": "sessions"}).round(3)


# Różnice S2 - S1 jednej metryki dla każdej pary (model, sesja); indeks (model, sesja) sprawia,
# że odejmowanie łączy wynik S2 i S1 tego samego modelu w tej samej sesji.
def paired_differences(results, metric):
    s1 = results[results["scenario"] == "S1"].set_index(["model", "test"])[metric]
    s2 = results[results["scenario"] == "S2"].set_index(["model", "test"])[metric]
    return (s2 - s1).dropna()


# S2 wobec S1 dla każdego modelu: średnia różnica FPR i recall oraz w ilu sesjach S2 jest lepsze.
# Lepsze = niższy FPR (mniej fałszywych alarmów) albo wyższy recall (więcej wykrytych ataków).
def compare_s2_with_s1(results):
    fpr, recall = paired_differences(results, "fpr"), paired_differences(results, "recall")
    rows = []
    for model, fpr_differences in fpr.groupby(level="model"):
        recall_differences = recall.loc[model]
        rows.append({"model": model, "sessions": len(fpr_differences),
                     "fpr_mean_difference": round(float(fpr_differences.mean()), 3),
                     "fpr_lower_in": int((fpr_differences < 0).sum()),
                     "recall_mean_difference": round(float(recall_differences.mean()), 3),
                     "recall_higher_in": int((recall_differences > 0).sum())})
    return pd.DataFrame(rows)


# Odstępy [s] między kolejnymi sesjami użytkownika jednego hosta i między heartbeatami IoT.
def session_gaps(log_path):
    user_times, heartbeat_times = [], []
    with open(log_path) as file:
        for line in file:
            record = json.loads(line)
            if record["action"] in USER_SESSIONS:
                user_times.append(record["t"])
            elif record["action"] == "iot_heartbeat":
                heartbeat_times.append(record["t"])
    return np.diff(sorted(user_times)), np.diff(sorted(heartbeat_times))


# CV i statystyka D testu K-S (rozkład wykładniczy) dla odstępów między sesjami; kontrast z IoT.
def traffic_realism(folders):
    user_gaps, heartbeat_gaps = [], []
    for folder in folders:
        for log_path in glob.glob(os.path.join(folder, "traffic_*.jsonl")):
            user, heartbeat = session_gaps(log_path)
            if len(user) > 1:
                user_gaps.append(user / user.mean())  # każdy host ma inną intensywność, więc normalizuję
            heartbeat_gaps.extend(heartbeat)
    rows = []
    if user_gaps:
        gaps = np.concatenate(user_gaps)
        # po normalizacji średnia = 1, więc porównuję ze standardowym rozkładem wykładniczym (średnia 1);
        # D = największa różnica między dystrybuantą empiryczną a wykładniczą
        rows.append({"traffic": "sesje użytkowników (odstępy / średnia hosta)", "gaps": len(gaps),
                     "cv": round(float(gaps.std() / gaps.mean()), 3),
                     "ks_d": round(float(stats.kstest(gaps, "expon").statistic), 3)})
    if len(heartbeat_gaps) > 1:
        gaps = np.asarray(heartbeat_gaps)
        rows.append({"traffic": "heartbeat IoT (s)", "gaps": len(gaps),
                     "cv": round(float(gaps.std() / gaps.mean()), 3), "ks_d": float("nan")})
    return pd.DataFrame(rows)


# Liczy wszystkie tabele dla jednego wariantu i zapisuje je jako CSV do results/stats/<wariant>/
# (te pliki czyta zakładka „Porównanie” w dashboardzie).
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", required=True, help="wariant zbioru źródłowego, np. cic albo cic+genis")
    parser.add_argument("--traffic", nargs="*", default=[], help="katalogi sesji z logami traffic_*.jsonl")
    args = parser.parse_args()
    folder = os.path.join(RESULTS, "stats", args.variant)
    os.makedirs(folder, exist_ok=True)

    results = load_results(args.variant, "metrics.csv")
    tables = {
        "summary": summarize_models(results),
        "fpr_by_session": results[["scenario", "test", "model", "fpr"]],
        "recall_per_attack": summarize_attacks(load_results(args.variant, "recall_per_attack.csv")),
        "s2_vs_s1": compare_s2_with_s1(results),
    }
    if args.traffic:
        tables["traffic_realism"] = traffic_realism(args.traffic)
    for name, table in tables.items():
        table.to_csv(os.path.join(folder, f"{name}.csv"), index=False)
        print(f"\n{name}:")
        print(table.to_string(index=False))
    print(f"\nZapisano: {folder}")


if __name__ == "__main__":
    main()
