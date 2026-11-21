#!/usr/bin/env python3
"""Statystyka wyników na sesjach testowych M1-M6 (jednostka = sesja).

Średnia +/- 95% przedział ufności po sesjach dla recall, FPR, FPR IoT, AUC-ROC i F1 (F1 tylko
pomocniczo, bo ataki to 84-91% przepływów). Do tego: FPR w każdej sesji, recall i AUC każdego ataku,
średni recall po atakach, S2 wobec S1 w tej samej sesji, macierze pomyłek i F1 klas RF, krzywe ROC,
wyniki modeli wobec progu, koszt oraz (z --traffic) realizm ruchu: CV i test K-S odstępów między sesjami.
Wynik do results/stats/<wariant>/ (czyta go dashboard, zakładka "Porównanie").

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
METRICS = ["recall", "fpr", "fpr_iot", "roc_auc", "f1"]  #f1 zależy od udziału ataków (opis wyżej)
CLASSES = ["normal", "port_scan", "ssh_bruteforce", "dos_slow", "http_flood", "c2_beaconing"]
ATTACKS = CLASSES[1:]
TARGET_FPR = 0.01  #FPR, przy którym liczę recall każdego ataku (recall_at_fpr)
MODELS = ["baseline", "IF", "RF", "FT"]
IOT_IP = "10.0.1.17"  #q2, heartbeat IoT (ten sam adres co IOT_IP w models/run_experiments.py)
#punkty FPR, w których zapisuję krzywą ROC: gęsto przy małym FPR (ważnym dla IDS) i równo na całej osi
FPR_GRID = np.unique(np.r_[np.logspace(-4, 0, 81), np.linspace(0, 1, 101)])
QUANTILES = {"q05": 0.05, "q25": 0.25, "q50": 0.5, "q75": 0.75, "q95": 0.95}
#miejsca po przecinku w zapisanych średnich: więcej niż w pracy i dashboardzie (3 albo 2), żeby liczba
#nie była zaokrąglana dwa razy (np. 0,4548 -> 0,455 w CSV -> 0,46 na wykresie zamiast 0,45);
#z tego samego powodu wskaźniki każdej sesji liczę od nowa z liczników i predykcji, a nie z metrics.csv
DECIMALS = 6


#średnia i połowa szerokości 95% przedziału ufności t-Studenta (n - 1 stopni swobody).
#przy n = 6 i wartościach bliskich 0 albo 1 przedział może wyjść poza [0, 1]; obejmuje tylko zmienność
#między sesjami testowymi (każdy model uczony raz), nie losowość treningu
def mean_with_ci(values):
    values = np.asarray(values, dtype=float)
    values = values[~np.isnan(values)]
    if len(values) == 0:
        return float("nan"), float("nan")
    if len(values) < 2:
        return float(values.mean()), float("nan")  #z jednej wartości nie da się policzyć rozrzutu
    #połowa przedziału = t(0,975; n-1) * odchylenie z próby / pierwiastek z n (przy n = 6: t ~ 2,571)
    half_width = stats.t.ppf(0.975, len(values) - 1) * values.std(ddof=1) / np.sqrt(len(values))
    return float(values.mean()), float(half_width)


#wiersze S1 (z run_experiments.py) i S2 (z run_s2.py), tylko sesje z Mininetu.
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


#tabela: scenariusz x model -> średnia +/- przedział dla każdej metryki.
def summarize_models(results):
    rows = []
    for (scenario, model), group in results.groupby(["scenario", "model"]):
        row = {"scenario": scenario, "model": model, "sessions": len(group)}
        for metric in METRICS:
            mean, half_width = mean_with_ci(group[metric])
            row[metric] = round(mean, DECIMALS)
            row[f"{metric}_ci95"] = round(half_width, DECIMALS)
        rows.append(row)
    return pd.DataFrame(rows)


#recall każdego ataku w każdej sesji z sum w macierzy pomyłek (alarm / brak alarmu);
#w recall_per_attack.csv jest zaokrąglony do 3 miejsc
def attack_recall(confusion):
    binary = confusion[(confusion["model"] != "RF (klasy)") & confusion["true"].isin(ATTACKS)]
    counts = binary.pivot_table(index=["scenario", "test", "model", "true"], columns="predicted",
                                values="count", aggfunc="sum", fill_value=0)
    alarms = counts["alarm"] if "alarm" in counts.columns else 0
    recall = (alarms / counts.sum(axis=1)).rename("recall").reset_index()
    return recall.rename(columns={"true": "attack"})


#recall każdego ataku: średnia po sesjach, dla każdego scenariusza i modelu.
def summarize_attacks(attack_results):
    table = attack_results.groupby(["scenario", "model", "attack"])["recall"].agg(["mean", "count"])
    return table.reset_index().rename(columns={"mean": "recall", "count": "sessions"}).round(DECIMALS)


#średni recall po atakach (macro): w każdej sesji średnia recall wszystkich ataków (5, z Z1) i samych
#znanych (A1-A4), potem średnia +/- 95% CI po sesjach. Recall ogólny liczy się na przepływach, więc
#dominują w nim liczne klasy (skan, flood); średnia po atakach daje każdemu atakowi tę samą wagę.
def macro_recall(attack_results):
    rows = []
    for (scenario, model), group in attack_results.groupby(["scenario", "model"]):
        all_attacks = group.groupby("test")["recall"].mean()
        known = group[group["attack"] != "c2_beaconing"].groupby("test")["recall"].mean()
        row = {"scenario": scenario, "model": model, "sessions": len(all_attacks)}
        for name, values in (("macro_recall", all_attacks), ("macro_recall_known", known)):
            mean, half_width = mean_with_ci(values)
            row[name], row[f"{name}_ci95"] = round(mean, DECIMALS), round(half_width, DECIMALS)
        rows.append(row)
    return pd.DataFrame(rows)


#recall, FPR i F1 liczone od nowa z TP, FN, FP, TN - w metrics.csv są zaokrąglone do 3 miejsc
#(FPR IoT i AUC-ROC liczy od nowa z predykcji exact_session_metrics)
def exact_rates(results):
    results = results.copy()
    results["recall"] = results["tp"] / (results["tp"] + results["fn"])
    results["fpr"] = results["fp"] / (results["fp"] + results["tn"])
    results["f1"] = 2 * results["tp"] / (2 * results["tp"] + results["fp"] + results["fn"])
    return results


#różnice S2 - S1 jednej metryki dla każdej pary (model, sesja); indeks (model, sesja) sprawia,
#że odejmowanie łączy wynik S2 i S1 tego samego modelu w tej samej sesji.
def paired_differences(results, metric):
    s1 = results[results["scenario"] == "S1"].set_index(["model", "test"])[metric]
    s2 = results[results["scenario"] == "S2"].set_index(["model", "test"])[metric]
    return (s2 - s1).dropna()


#S2 wobec S1 dla każdego modelu: średnia różnica FPR i recall oraz w ilu sesjach S2 jest lepsze,
#a w ilu jest remis (ta sama wartość). Lepsze = niższy FPR (mniej fałszywych alarmów) albo wyższy
#recall (więcej wykrytych ataków).
def compare_s2_with_s1(results):
    results = exact_rates(results)
    fpr, recall = paired_differences(results, "fpr"), paired_differences(results, "recall")
    rows = []
    for model, fpr_differences in fpr.groupby(level="model"):
        recall_differences = recall.loc[model]
        rows.append({"model": model, "sessions": len(fpr_differences),
                     "fpr_mean_difference": round(float(fpr_differences.mean()), DECIMALS),
                     "fpr_lower_in": int((fpr_differences < 0).sum()),
                     "fpr_equal_in": int((fpr_differences == 0).sum()),
                     "recall_mean_difference": round(float(recall_differences.mean()), DECIMALS),
                     "recall_higher_in": int((recall_differences > 0).sum()),
                     "recall_equal_in": int((recall_differences == 0).sum())})
    return pd.DataFrame(rows)


#macierze pomyłek zsumowane po sesjach M1-M6: scenariusz, model, prawdziwa klasa, decyzja, liczba.
def summarize_confusion(confusion):
    return confusion.groupby(["scenario", "model", "true", "predicted"], as_index=False)["count"].sum()


#F1 każdej klasy z macierzy 6 x 6 RF (model "RF (klasy)") i średnie F1 po klasach (macro-F1).
#F1 klasy = 2 TP / (2 TP + FP + FN); dla c2_beaconing (RF jej nie przewiduje) wychodzi 0.
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
            rows.append({"scenario": scenario, "class": name, "flows": int(tp + fn), "f1": round(float(f1), DECIMALS)})
        rows.append({"scenario": scenario, "class": "macro-F1", "flows": int(matrix["count"].sum()),
                     "f1": round(float(np.nanmean(scores)), DECIMALS)})
        #bez c2_beaconing: tej klasy nie ma w treningu, więc jej F1 = 0 z założenia, nie z błędu modelu
        known = [score for name, score in zip(CLASSES, scores) if name != "c2_beaconing"]
        rows.append({"scenario": scenario, "class": "macro-F1 (bez c2)", "flows": int(matrix["count"].sum()),
                     "f1": round(float(np.nanmean(known)), DECIMALS)})
    return pd.DataFrame(rows)


#okna, w których worker hosta stał: na czas ataku z tego hosta run_session.py wysyła mu SIGSTOP,
#a po ataku SIGCONT (rotacja o3, d2, o5); host -> lista (start, koniec) z ground_truth.jsonl sesji
def frozen_windows(folder):
    windows = {}
    path = os.path.join(folder, "ground_truth.jsonl")
    if os.path.exists(path):
        with open(path) as file:
            for line in file:
                if line.strip():
                    record = json.loads(line)
                    windows.setdefault(record["attacker"], []).append((record["start"], record["end"]))
    return windows


#odstępy [s] między startami kolejnych sesji użytkownika jednego hosta i między heartbeatami IoT.
#start = chwila startu sesji (worker.loop_sessions), także w rekordach błędów (mail_send_error,
#session_error); t to chwila zapisu, czyli koniec sesji. Pomijam odstęp, który nachodzi na okno
#wstrzymania hosta (frozen): jest wydłużony przez zatrzymanie workera, a nie przez losowanie.
#bez zapasu wokół okna: SIGSTOP idzie przed zapisanym startem ataku, a SIGCONT po zapisanym końcu, więc
#żaden start sesji nie wypada w okno; odstęp zaczęty zaraz po SIGCONT jest zwykłym losowaniem i zostaje
def session_gaps(log_path, frozen=()):
    user_times, heartbeat_times = [], []
    with open(log_path) as file:
        for line in file:
            record = json.loads(line)
            if "start" in record:
                user_times.append(record["start"])
            elif record["action"] == "iot_heartbeat":
                heartbeat_times.append(record["t"])
    user_times = np.sort(user_times)
    keep = np.ones(max(len(user_times) - 1, 0), dtype=bool)
    for start, end in frozen:
        keep &= ~((user_times[:-1] < end) & (user_times[1:] > start))
    return np.diff(user_times)[keep], np.diff(sorted(heartbeat_times))


#CV i statystyka D testu K-S (rozkład wykładniczy) dla odstępów między sesjami; kontrast z IoT.
#zwraca tabelę podsumowania i same odstępy (do histogramu).
def traffic_realism(folders):
    user_gaps, heartbeat_gaps = [], []
    for folder in folders:
        frozen = frozen_windows(folder)
        for log_path in glob.glob(os.path.join(folder, "traffic_*.jsonl")):
            host = os.path.basename(log_path)[len("traffic_"):-len(".jsonl")]
            user, heartbeat = session_gaps(log_path, frozen.get(host, ()))
            if len(user) > 1:
                user_gaps.append(user / user.mean())  #każdy host ma inną intensywność, więc normalizuję
            heartbeat_gaps.extend(heartbeat)
    rows, gap_tables = [], []
    if user_gaps:
        gaps = np.concatenate(user_gaps)
        #po normalizacji średnia = 1, więc porównuję ze standardowym rozkładem wykładniczym (średnia 1);
        #D = największa różnica między dystrybuantą empiryczną a wykładniczą
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


#S0 z run_experiments.py (test na ostatnich 30% każdego fragmentu (nagranie, klasa) zbioru źródłowego;
#w wariancie CIC + GeNIS dwa testy). Recall, FPR i F1 z liczników; AUC-ROC zostaje z metrics.csv
#(3 miejsca), bo predykcji S0 run_experiments.py nie zapisuje.
def s0_results(variant):
    path = os.path.join(RESULTS, "S0_S1", variant, "metrics.csv")
    if not os.path.exists(path):
        return None
    results = exact_rates(pd.read_csv(path))
    results = results[results["scenario"] == "S0"][["test", "model", "recall", "fpr", "roc_auc", "f1"]]
    return results.round(DECIMALS)


#predykcje S1 i S2 ze wszystkich sesji testowych (results/raw/<scenariusz>_<wariant>_<sesja>/) i progi.
#progi są wspólne dla wszystkich sesji jednego scenariusza (model nie zmienia się między sesjami).
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
            flows["session"] = session
            tables.append(flows)
            with open(os.path.join(folder, "thresholds.json")) as file:
                thresholds[scenario] = json.load(file)
    return (pd.concat(tables, ignore_index=True) if tables else None), thresholds


#krzywe ROC (wszystkie sesje razem) i punkt pracy każdego modelu (FPR i TPR przy progu z walidacji)
#krzywą zapisuję w punktach FPR_GRID: dla każdego FPR największy osiągalny TPR
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
                           "fpr": round(float(alarm[labels == 0].mean()), DECIMALS),
                           "tpr": round(float(alarm[labels == 1].mean()), DECIMALS),
                           "roc_auc": round(float(roc_auc_score(labels, scores)), DECIMALS)})
    return pd.DataFrame(curves), pd.DataFrame(points)


#AUC-ROC i FPR IoT każdej sesji od nowa z predykcji i progów (w metrics.csv są zaokrąglone do 3 miejsc)
def exact_session_metrics(predictions, thresholds):
    rows = []
    for (scenario, session), flows in predictions.groupby(["scenario", "session"]):
        labels = flows["label"].to_numpy()
        iot_normal = (flows["src_ip"] == IOT_IP).to_numpy() & (labels == 0)
        for model in MODELS:
            scores = flows[f"score_{model}"].to_numpy()
            alarm = scores[iot_normal] > thresholds[scenario][model]
            rows.append({"scenario": scenario, "test": session, "model": model,
                         "roc_auc": float(roc_auc_score(labels, scores)),
                         "fpr_iot": float(alarm.mean()) if iot_normal.any() else float("nan")})
    return pd.DataFrame(rows)


#wyniki z metrics.csv z AUC-ROC i FPR IoT podmienionymi na dokładne wartości (dla sesji z predykcjami)
def with_exact_metrics(results, exact):
    keys = ["scenario", "test", "model"]
    results = results.set_index(keys)
    results.update(exact.set_index(keys)[["roc_auc", "fpr_iot"]])
    return results.reset_index()


#kwantyle wyników modeli w czterech grupach przepływów i próg (do wykresu "wynik a próg"):
#ruch normalny bez IoT, heartbeat IoT (legalny, ale regularny), Z1 (atak niewidziany) i znane ataki.
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


#średnia +/- 95% CI po sesjach jednej wartości liczonej osobno w każdej sesji (kolumna value).
def per_session_summary(per_session, keys, value):
    rows = []
    for key, group in per_session.groupby(keys):
        mean, half_width = mean_with_ci(group[value])
        rows.append({**dict(zip(keys, key)), "sessions": len(group),
                     value: round(mean, DECIMALS), f"{value}_ci95": round(half_width, DECIMALS)})
    return pd.DataFrame(rows)


#AUC-ROC każdego ataku osobno (atak vs ruch normalny tej samej sesji), średnia +/- 95% CI po sesjach
#wspólne AUC zdominowane jest przez skan (ok. 70% przepływów ataków), więc słabe wyniki SSH i Z1 w nim giną
def auc_per_attack(predictions):
    rows = []
    for (scenario, session), flows in predictions.groupby(["scenario", "session"]):
        normal = flows[flows["label"] == 0]
        for attack in ATTACKS:
            part = flows[flows["attack_type"] == attack]
            if part.empty or normal.empty:
                continue
            labels = np.r_[np.zeros(len(normal)), np.ones(len(part))]
            for model in MODELS:
                scores = np.r_[normal[f"score_{model}"].to_numpy(), part[f"score_{model}"].to_numpy()]
                rows.append({"scenario": scenario, "session": session, "model": model, "attack": attack,
                             "auc": float(roc_auc_score(labels, scores))})
    return per_session_summary(pd.DataFrame(rows), ["scenario", "model", "attack"], "auc")


#próg, nad którym jest najwyżej 1% wyników ruchu normalnego (alarm = wynik > próg)
#przy remisach (np. RF ma wyniki skokowe) FPR może wyjść niższy, dlatego zapisuję go obok
def threshold_at_fpr(normal_scores, target=TARGET_FPR):
    ordered = np.sort(np.asarray(normal_scores))[::-1]
    return ordered[min(int(np.floor(target * len(ordered))), len(ordered) - 1)]


#recall każdego ataku przy FPR 1%, z progiem dobranym na teście tej sesji - to nie wynik do wdrożenia,
#tylko ile model mógłby wykryć przy idealnie ustawionym progu; "wszystkie" = wszystkie przepływy ataków
def recall_at_fpr(predictions):
    rows = []
    for (scenario, session), flows in predictions.groupby(["scenario", "session"]):
        is_normal = (flows["label"] == 0).to_numpy()
        attack_types = flows["attack_type"].to_numpy()
        for model in MODELS:
            scores = flows[f"score_{model}"].to_numpy()
            alarm = scores > threshold_at_fpr(scores[is_normal])
            base = {"scenario": scenario, "session": session, "model": model, "fpr": float(alarm[is_normal].mean())}
            rows.append({**base, "attack": "wszystkie", "recall": float(alarm[~is_normal].mean())})
            for attack in ATTACKS:
                mask = attack_types == attack
                if mask.any():
                    rows.append({**base, "attack": attack, "recall": float(alarm[mask].mean())})
    per_session = pd.DataFrame(rows)
    keys = ["scenario", "model", "attack"]
    fpr = per_session.groupby(keys)["fpr"].mean().round(DECIMALS).reset_index()
    return per_session_summary(per_session, keys, "recall").merge(fpr, on=keys)


#koszt: średni czas treningu (S1) albo adaptacji (S2) i przepustowość predykcji, średnio po sesjach.
def cost_table(results):
    return results.groupby(["scenario", "model"], as_index=False)[["train_seconds", "flows_per_second"]].mean()


#liczy wszystkie tabele dla jednego wariantu i zapisuje je jako CSV do results/stats/<wariant>/
#(te pliki czyta zakładka "Porównanie" w dashboardzie).
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", required=True, help="wariant zbioru źródłowego, np. cic albo cic+genis")
    parser.add_argument("--traffic", nargs="*", default=[], help="katalogi sesji z logami traffic_*.jsonl")
    args = parser.parse_args()
    folder = os.path.join(RESULTS, "stats", args.variant)
    os.makedirs(folder, exist_ok=True)

    results = load_results(args.variant, "metrics.csv")
    predictions, thresholds = load_predictions(args.variant, sorted(results["test"].unique()))
    if predictions is not None:
        results = with_exact_metrics(results, exact_session_metrics(predictions, thresholds))
    raw_confusion = load_results(args.variant, "confusion.csv")
    attack_results = attack_recall(raw_confusion)
    tables = {
        "summary": summarize_models(exact_rates(results)),
        "fpr_by_session": exact_rates(results)[["scenario", "test", "model", "fpr"]].round(DECIMALS),
        "recall_per_attack": summarize_attacks(attack_results),
        "macro_recall": macro_recall(attack_results),
        "s2_vs_s1": compare_s2_with_s1(results),
    }
    confusion = summarize_confusion(raw_confusion)
    tables["confusion"] = confusion
    tables["rf_class_f1"] = rf_class_f1(confusion)
    tables["cost"] = cost_table(results)
    s0 = s0_results(args.variant)
    if s0 is not None:
        tables["s0"] = s0
    long_tables = {}  #duże tabele tylko do pliku (do wykresów), bez wypisywania
    if predictions is not None:
        long_tables["roc_curves"], tables["roc_points"] = roc_tables(predictions, thresholds)
        tables["score_quantiles"] = score_quantiles(predictions, thresholds)
        tables["auc_per_attack"] = auc_per_attack(predictions)
        tables["recall_at_fpr1"] = recall_at_fpr(predictions)
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
