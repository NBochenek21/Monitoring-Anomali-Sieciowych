#!/usr/bin/env python3
"""Porównanie modeli na sesjach testowych z Mininetu (M1-M6).

Jednostka = sesja: każda sesja to osobny zbiór testowy, więc wynik modelu to średnia z sesji,
a rozrzut między sesjami pokazuje, na ile wynik jest stabilny.

Miary główne nie zależą od udziału ataków w teście: recall (TPR) liczy się wyłącznie na przepływach
ataku, FPR wyłącznie na ruchu normalnym, a AUC-ROC to pole pod krzywą TPR(FPR) po wszystkich progach,
więc też nie zmienia się z proporcją klas i nie zależy od wybranego progu. W sesjach M1-M6 ataki to
84-91% przepływów (w prawdziwej sieci ruch normalny dominuje), dlatego F1 (przez precision) jest tu
zawyżony: raportuję go na prośbę koordynatora jako miarę pomocniczą, z tym zastrzeżeniem. PR-AUC
i precision zostają tylko w metrics.csv. FPR jako miara operacyjna: Sommer i Paxson 2010 (koszt
fałszywych alarmów); miary dopasowane do niezbalansowania: Arp i in. 2022 (P7, P8). Liczę:
  1. średnią i 95% przedział ufności t-Studenta (średnia ± połowa szerokości przedziału) dla recall,
     FPR, FPR dla heartbeatu IoT, AUC-ROC i F1, osobno S1 i S2,
  2. FPR każdego modelu w każdej sesji (do wykresu: widać, czy wynik jest stały między sesjami),
  3. recall każdego ataku (w tym Z1, atak niewidziany): średnia po sesjach (do heatmapy model x atak)
     oraz średni recall po atakach (każdy atak z tą samą wagą, z Z1 i bez Z1) ± 95% CI,
  4. S2 wobec S1 dla każdego modelu (pary: ta sama sesja): średnia różnica FPR i recall oraz w ilu
     sesjach S2 wypadło lepiej (FPR niżej, recall wyżej), a w ilu był remis. Różnice liczę
     z dokładnych liczb TP, FP, FN, TN, a nie z metryk zaokrąglonych do 3 miejsc w metrics.csv,
     więc remis to naprawdę ta sama wartość,
  5. macierze pomyłek zsumowane po sesjach M1-M6: dla każdego modelu prawdziwa klasa (6 klas: normal
     i 5 ataków) × decyzja (alarm / brak alarmu), a dla RF także prawdziwa klasa × przewidziana klasa
     (macierz 6 × 6; kolumna c2_beaconing jest pusta, bo tej klasy nie ma w treningu); z niej F1
     każdej klasy i średnie F1 po klasach (macro-F1) dla RF,
  6. (opcjonalnie, --traffic) realizm generatora ruchu: odstępy między startami sesji użytkownika
     każdego hosta (logi traffic_*.jsonl, pole start). Dla procesu Poissona odstępy są wykładnicze: współczynnik
     zmienności (CV) ok. 1 i mała statystyka D testu Kołmogorowa-Smirnowa. Kontrast: heartbeat IoT
     (prawie stałe odstępy, CV ok. 0). Generator losuje odstępy z rozkładu wykładniczego, więc ten
     pomiar sprawdza, że ruch w nagraniu zgadza się z projektem i z modelem Poissona dla sesji
     użytkownika (Paxson i Floyd 1995), a nie podobieństwo do ruchu konkretnej prawdziwej firmy.
     Same odstępy też trafiają do pliku (histogram w dashboardzie),
  7. S0 (test na końcówce zbioru źródłowego) jako punkt odniesienia dla S1 i S2,
  8. z predykcji results/raw/ (wszystkie sesje M1-M6 razem): krzywe ROC z punktem pracy (próg z walidacji)
     oraz rozkład wyników modeli (kwantyle) dla ruchu normalnego, heartbeatu IoT, Z1 i znanych ataków
     wobec progu - pokazuje, czy zawodzi uporządkowanie przepływów, czy sam próg,
  9. koszt: czas treningu i przepustowość (średnio na sesję).

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
from sklearn.metrics import roc_auc_score, roc_curve

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "..", "results")
METRICS = ["recall", "fpr", "fpr_iot", "roc_auc", "f1"]  # f1 zależy od udziału ataków (opis wyżej)
CLASSES = ["normal", "port_scan", "ssh_bruteforce", "dos_slow", "http_flood", "c2_beaconing"]
USER_SESSIONS = ["web_browse", "dns_lookup", "mail_send", "ssh_work", "file_transfer", "ssh_admin"]
MODELS = ["baseline", "IF", "RF", "FT"]
IOT_IP = "10.0.1.17"  # q2, heartbeat IoT (ten sam adres co IOT_IP w models/run_experiments.py)
# punkty FPR, w których zapisuję krzywą ROC: gęsto przy małym FPR (ważnym dla IDS) i równo na całej osi
FPR_GRID = np.unique(np.r_[np.logspace(-4, 0, 81), np.linspace(0, 1, 101)])
QUANTILES = {"q05": 0.05, "q25": 0.25, "q50": 0.5, "q75": 0.75, "q95": 0.95}


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


# Średni recall po atakach (macro): w każdej sesji średnia recall wszystkich ataków (5, z Z1) i samych
# znanych (A1-A4), potem średnia ± 95% CI po sesjach. Recall ogólny liczy się na przepływach, więc
# dominują w nim liczne klasy (skan, flood); średnia po atakach daje każdemu atakowi tę samą wagę.
def macro_recall(attack_results):
    rows = []
    for (scenario, model), group in attack_results.groupby(["scenario", "model"]):
        all_attacks = group.groupby("test")["recall"].mean()
        known = group[group["attack"] != "c2_beaconing"].groupby("test")["recall"].mean()
        row = {"scenario": scenario, "model": model, "sessions": len(all_attacks)}
        for name, values in (("macro_recall", all_attacks), ("macro_recall_known", known)):
            mean, half_width = mean_with_ci(values)
            row[name], row[f"{name}_ci95"] = round(mean, 3), round(half_width, 3)
        rows.append(row)
    return pd.DataFrame(rows)


# Dokładne recall i FPR z liczb TP, FN, FP, TN (metrics.csv ma te metryki zaokrąglone do 3 miejsc).
def exact_rates(results):
    results = results.copy()
    results["recall"] = results["tp"] / (results["tp"] + results["fn"])
    results["fpr"] = results["fp"] / (results["fp"] + results["tn"])
    return results


# Różnice S2 - S1 jednej metryki dla każdej pary (model, sesja); indeks (model, sesja) sprawia,
# że odejmowanie łączy wynik S2 i S1 tego samego modelu w tej samej sesji.
def paired_differences(results, metric):
    s1 = results[results["scenario"] == "S1"].set_index(["model", "test"])[metric]
    s2 = results[results["scenario"] == "S2"].set_index(["model", "test"])[metric]
    return (s2 - s1).dropna()


# S2 wobec S1 dla każdego modelu: średnia różnica FPR i recall oraz w ilu sesjach S2 jest lepsze,
# a w ilu jest remis (ta sama wartość). Lepsze = niższy FPR (mniej fałszywych alarmów) albo wyższy
# recall (więcej wykrytych ataków).
def compare_s2_with_s1(results):
    results = exact_rates(results)
    fpr, recall = paired_differences(results, "fpr"), paired_differences(results, "recall")
    rows = []
    for model, fpr_differences in fpr.groupby(level="model"):
        recall_differences = recall.loc[model]
        rows.append({"model": model, "sessions": len(fpr_differences),
                     "fpr_mean_difference": round(float(fpr_differences.mean()), 3),
                     "fpr_lower_in": int((fpr_differences < 0).sum()),
                     "fpr_equal_in": int((fpr_differences == 0).sum()),
                     "recall_mean_difference": round(float(recall_differences.mean()), 3),
                     "recall_higher_in": int((recall_differences > 0).sum()),
                     "recall_equal_in": int((recall_differences == 0).sum())})
    return pd.DataFrame(rows)


# Macierze pomyłek zsumowane po sesjach M1-M6: scenariusz, model, prawdziwa klasa, decyzja, liczba.
def summarize_confusion(confusion):
    return confusion.groupby(["scenario", "model", "true", "predicted"], as_index=False)["count"].sum()


# F1 każdej klasy z macierzy 6 × 6 RF (model "RF (klasy)") i średnie F1 po klasach (macro-F1).
# F1 klasy = 2 TP / (2 TP + FP + FN); dla c2_beaconing (RF jej nie przewiduje) wychodzi 0.
def rf_class_f1(confusion):
    rows = []
    for scenario, matrix in confusion[confusion["model"] == "RF (klasy)"].groupby("scenario"):
        scores = []
        for name in CLASSES:
            tp = matrix[(matrix["true"] == name) & (matrix["predicted"] == name)]["count"].sum()
            fp = matrix[(matrix["true"] != name) & (matrix["predicted"] == name)]["count"].sum()
            fn = matrix[(matrix["true"] == name) & (matrix["predicted"] != name)]["count"].sum()
            f1 = 2 * tp / (2 * tp + fp + fn) if tp + fp + fn else float("nan")
            scores.append(f1)
            rows.append({"scenario": scenario, "class": name, "flows": int(tp + fn), "f1": round(float(f1), 3)})
        rows.append({"scenario": scenario, "class": "macro-F1", "flows": int(matrix["count"].sum()),
                     "f1": round(float(np.nanmean(scores)), 3)})
        # bez c2_beaconing: tej klasy nie ma w treningu, więc jej F1 = 0 z założenia, nie z błędu modelu
        known = [score for name, score in zip(CLASSES, scores) if name != "c2_beaconing"]
        rows.append({"scenario": scenario, "class": "macro-F1 (bez c2)", "flows": int(matrix["count"].sum()),
                     "f1": round(float(np.nanmean(known)), 3)})
    return pd.DataFrame(rows)


# Odstępy [s] między startami kolejnych sesji użytkownika jednego hosta i między heartbeatami IoT.
# start = chwila startu sesji (worker.loop_sessions); t to chwila zapisu, czyli koniec sesji.
def session_gaps(log_path):
    user_times, heartbeat_times = [], []
    with open(log_path) as file:
        for line in file:
            record = json.loads(line)
            if record["action"] in USER_SESSIONS:
                user_times.append(record["start"])
            elif record["action"] == "iot_heartbeat":
                heartbeat_times.append(record["t"])
    return np.diff(sorted(user_times)), np.diff(sorted(heartbeat_times))


# CV i statystyka D testu K-S (rozkład wykładniczy) dla odstępów między sesjami; kontrast z IoT.
# Zwraca tabelę podsumowania i same odstępy (do histogramu).
def traffic_realism(folders):
    user_gaps, heartbeat_gaps = [], []
    for folder in folders:
        for log_path in glob.glob(os.path.join(folder, "traffic_*.jsonl")):
            user, heartbeat = session_gaps(log_path)
            if len(user) > 1:
                user_gaps.append(user / user.mean())  # każdy host ma inną intensywność, więc normalizuję
            heartbeat_gaps.extend(heartbeat)
    rows, gap_tables = [], []
    if user_gaps:
        gaps = np.concatenate(user_gaps)
        # po normalizacji średnia = 1, więc porównuję ze standardowym rozkładem wykładniczym (średnia 1);
        # D = największa różnica między dystrybuantą empiryczną a wykładniczą
        rows.append({"traffic": "sesje użytkowników (odstępy / średnia hosta)", "gaps": len(gaps),
                     "cv": round(float(gaps.std() / gaps.mean()), 3),
                     "ks_d": round(float(stats.kstest(gaps, "expon").statistic), 3)})
        gap_tables.append(pd.DataFrame({"traffic": "sesje użytkowników", "gap": gaps.round(4)}))
    if len(heartbeat_gaps) > 1:
        gaps = np.asarray(heartbeat_gaps)
        rows.append({"traffic": "heartbeat IoT (s)", "gaps": len(gaps),
                     "cv": round(float(gaps.std() / gaps.mean()), 3), "ks_d": float("nan")})
        gap_tables.append(pd.DataFrame({"traffic": "heartbeat IoT", "gap": gaps.round(3)}))
    return pd.DataFrame(rows), pd.concat(gap_tables, ignore_index=True) if gap_tables else None


# S0 z run_experiments.py (test na końcówce zbioru źródłowego; w wariancie CIC + GeNIS dwa testy).
def s0_results(variant):
    path = os.path.join(RESULTS, "S0_S1", variant, "metrics.csv")
    if not os.path.exists(path):
        return None
    results = pd.read_csv(path)
    return results[results["scenario"] == "S0"][["test", "model", "recall", "fpr", "roc_auc", "f1"]]


# Predykcje S1 i S2 ze wszystkich sesji testowych (results/raw/<scenariusz>_<wariant>_<sesja>/) i progi.
# Progi są wspólne dla wszystkich sesji jednego scenariusza (model nie zmienia się między sesjami).
def load_predictions(variant, sessions):
    tables, thresholds = [], {}
    columns = ["label", "attack_type", "src_ip"] + [f"score_{model}" for model in MODELS]
    for scenario in ("S1", "S2"):
        for session in sessions:
            folder = os.path.join(RESULTS, "raw", f"{scenario}_{variant}_{session}")
            if not os.path.exists(os.path.join(folder, "predictions.parquet")):
                continue
            flows = pd.read_parquet(os.path.join(folder, "predictions.parquet"), columns=columns)
            flows["scenario"] = scenario
            tables.append(flows)
            with open(os.path.join(folder, "thresholds.json")) as file:
                thresholds[scenario] = json.load(file)
    return (pd.concat(tables, ignore_index=True) if tables else None), thresholds


# Krzywe ROC (przepływy wszystkich sesji razem) i punkt pracy każdego modelu: FPR i TPR przy progu
# z walidacji. Krzywą zapisuję w punktach FPR_GRID: dla każdego FPR największy TPR osiągalny przy
# FPR nie większym (krzywa schodkowa, jak z roc_curve).
def roc_tables(predictions, thresholds):
    curves, points = [], []
    for scenario, group in predictions.groupby("scenario"):
        labels = group["label"].to_numpy()
        for model in MODELS:
            scores = group[f"score_{model}"].to_numpy()
            fpr, tpr, _ = roc_curve(labels, scores)
            curve_tpr = tpr[np.searchsorted(fpr, FPR_GRID, side="right") - 1]
            curves += [{"scenario": scenario, "model": model, "fpr": round(float(x), 5), "tpr": round(float(y), 5)}
                       for x, y in zip(FPR_GRID, curve_tpr)]
            alarm = scores > thresholds[scenario][model]
            points.append({"scenario": scenario, "model": model,
                           "fpr": round(float(alarm[labels == 0].mean()), 4),
                           "tpr": round(float(alarm[labels == 1].mean()), 4),
                           "roc_auc": round(float(roc_auc_score(labels, scores)), 4)})
    return pd.DataFrame(curves), pd.DataFrame(points)


# Kwantyle wyników modeli w czterech grupach przepływów i próg (do wykresu „wynik a próg”):
# ruch normalny bez IoT, heartbeat IoT (legalny, ale regularny), Z1 (atak niewidziany) i znane ataki.
def score_quantiles(predictions, thresholds):
    is_normal = predictions["label"] == 0
    groups = np.where(is_normal, np.where(predictions["src_ip"] == IOT_IP, "heartbeat IoT", "ruch normalny"),
                      np.where(predictions["attack_type"] == "c2_beaconing", "Z1 c2_beaconing", "znane ataki"))
    rows = []
    for (scenario, group), flows in predictions.groupby([predictions["scenario"], groups]):
        for model in MODELS:
            scores = flows[f"score_{model}"]
            rows.append({"scenario": scenario, "model": model, "group": group, "flows": len(flows),
                         **{name: float(scores.quantile(q)) for name, q in QUANTILES.items()},
                         "threshold": float(thresholds[scenario][model])})
    return pd.DataFrame(rows)


# Koszt: średni czas treningu (S1) albo adaptacji (S2) i przepustowość predykcji, średnio po sesjach.
def cost_table(results):
    return results.groupby(["scenario", "model"], as_index=False)[["train_seconds", "flows_per_second"]].mean()


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
    attack_results = load_results(args.variant, "recall_per_attack.csv")
    tables = {
        "summary": summarize_models(results),
        "fpr_by_session": results[["scenario", "test", "model", "fpr"]],
        "recall_per_attack": summarize_attacks(attack_results),
        "macro_recall": macro_recall(attack_results),
        "s2_vs_s1": compare_s2_with_s1(results),
    }
    confusion = summarize_confusion(load_results(args.variant, "confusion.csv"))
    tables["confusion"] = confusion
    tables["rf_class_f1"] = rf_class_f1(confusion)
    tables["cost"] = cost_table(results)
    s0 = s0_results(args.variant)
    if s0 is not None:
        tables["s0"] = s0
    long_tables = {}  # duże tabele tylko do pliku (do wykresów), bez wypisywania
    predictions, thresholds = load_predictions(args.variant, sorted(results["test"].unique()))
    if predictions is not None:
        long_tables["roc_curves"], tables["roc_points"] = roc_tables(predictions, thresholds)
        tables["score_quantiles"] = score_quantiles(predictions, thresholds)
    if args.traffic:
        tables["traffic_realism"], gaps = traffic_realism(args.traffic)
        if gaps is not None:
            long_tables["traffic_gaps"] = gaps
    for name, table in tables.items():
        table.to_csv(os.path.join(folder, f"{name}.csv"), index=False)
        print(f"\n{name}:")
        print(table.to_string(index=False))
    for name, table in long_tables.items():
        table.to_csv(os.path.join(folder, f"{name}.csv"), index=False)
        print(f"\n{name}: {len(table)} wierszy (tylko w pliku)")
    print(f"\nZapisano: {folder}")


if __name__ == "__main__":
    main()
