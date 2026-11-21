#!/usr/bin/env python3
"""Tabele liczbowe pracy w LaTeX-u, liczone prosto z danych i wyników (bez przepisywania liczb).

Każda tabela to plik praca/tabele/<nazwa>.tex z samym tabular; podpis i etykietę dodaje się w tekście
przez input. Liczby po polsku: przecinek dziesiętny, odstęp co trzy cyfry od 10 000.
Źródła: zbiory źródłowe (liczności klas, próbka), sesje z Mininetu (sesje, skład klas, ataki, mediany
cech kontekstu) i wyniki statystyki (metryki, S2 wobec S1, recall per atak, koszt, realizm).

Uruchamianie w WSL (pyarrow):
    /root/venvs/ft/bin/python stats/tables.py
    /root/venvs/ft/bin/python stats/tables.py --only results
"""
import argparse
import glob
import json
import os
import re
import sys
from decimal import ROUND_HALF_UP, Decimal

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
RESULTS = os.path.join(REPO, "results")
FLOWS = os.path.join(REPO, "data", "flows")
sys.path[:0] = [os.path.join(REPO, "models"), os.path.join(REPO, "features")]

from summarize import IOT_IP, MODELS  #noqa: E402

VARIANTS = {"cic": "CIC", "cic+genis": "CIC + GeNIS"}
SOURCES = {"cic": "CIC-IDS2017", "genis": "GeNIS"}
SESSIONS = ["M0", "M1", "M2", "M3", "M4", "M5", "M6"]
TEST_SESSIONS = SESSIONS[1:]
ATTACKS = ["port_scan", "ssh_bruteforce", "dos_slow", "http_flood", "c2_beaconing"]
NOT_USED = ["attempted", "poza_zakresem"]
CLASS_NAMES = {
    "normal": "ruch normalny",
    "port_scan": "A1 skan portów",
    "ssh_bruteforce": "A2 brute-force SSH",
    "dos_slow": "A3 wolny DoS",
    "http_flood": "A4 HTTP flood",
    "c2_beaconing": "Z1 beaconing C2",
    "attempted": "attempted (usuwane)",
    "poza_zakresem": "poza zakresem (usuwane)",
}
SOURCE_CLASSES = ["normal", "port_scan", "ssh_bruteforce", "dos_slow", "http_flood"]
HEADER = "% plik wygenerowany przez stats/tables.py; zmiany wprowadzać w skrypcie, nie tutaj\n"


#---------------------------------------------------------------- liczby po polsku

#zaokrąglenie połówek w górę na zapisie dziesiętnym liczby (0,0075 -> 0,008), a nie na binarnym,
#w którym 0,0075 jest odrobinę mniejsze i format Pythona daje 0,007
def rounded(x, places):
    return Decimal(repr(float(x))).quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_UP)


#liczba z przecinkiem dziesiętnym; minus jako znak matematyczny
def number(x, places=3):
    if x is None or pd.isna(x):
        return "--"
    text = str(rounded(x, places))
    if float(text) == 0:  #bez "-0,000"
        text = text.lstrip("-")
    text = text.replace(".", ",")
    #minus tekstowy (\textminus), nie $-...$: w trybie matematycznym cyfry byłyby krojem Computer Modern,
    #a nie Times jak reszta tabeli, i przecinek dostałby odstęp za sobą
    return "\\textminus{}" + text[1:] if text.startswith("-") else text


#liczba całkowita; od 10 000 cyfry w grupach po trzy oddzielone wąską spacją
def integer(n):
    n = int(rounded(n, 0))
    if abs(n) < 10000:
        return str(n)
    return f"{n:,}".replace(",", "\\,")


#średnia +/- połowa 95% przedziału ufności (bez przedziału, gdy go nie ma)
def mean_ci(mean, half_width, places=3):
    if pd.isna(half_width):
        return number(mean, places)
    return f"{number(mean, places)}$\\,\\pm\\,${number(half_width, places)}"  #wąskie spacje: węższa tabela


#różnica ze znakiem: "+0,321" albo z minusem tekstowym
def signed(x, places=3):
    text = number(x, places)
    return text if text.startswith("\\textminus") else "+" + text


def seconds(x):
    if x < 0.1:
        return "$<0{,}1$"
    return number(x, 1) if x < 10 else integer(x)


def per_second(x):
    if x >= 1e6:
        return f"{number(x / 1e6, 1)} mln"
    if x >= 1e5:
        return f"{integer(x / 1e3)} tys."
    return f"{number(x / 1e3, 1)} tys."


def percent(x):
    if 0 < x < 0.005:
        return "$<1$\\%"  #nie "0%", gdy jakieś przepływy są
    return f"{rounded(x * 100, 0)}\\%"


#---------------------------------------------------------------- zapis tabeli

#nagłówek kolumny w kilku liniach (znak nowej linii w tekście), żeby tabela zmieściła się w kolumnie
def stacked(cell):
    if "\n" not in cell:
        return cell
    #"{}" po \\, żeby linia zaczynająca się od "[" (np. "[MB]") nie była wzięta za odstęp \\[...]
    return "\\begin{tabular}[b]{@{}c@{}}" + " \\\\ {}".join(cell.split("\n")) + "\\end{tabular}"


#nazwy klas w nagłówkach kolumn, w kilku liniach (węższa tabela)
CLASS_HEADERS = {
    "normal": "ruch\nnormalny",
    "port_scan": "A1\nskan portów",
    "ssh_bruteforce": "A2\nbrute-force\nSSH",
    "dos_slow": "A3\nwolny DoS",
    "http_flood": "A4\nHTTP flood",
    "c2_beaconing": "Z1\nbeaconing C2",
}


def class_header(name):
    return CLASS_HEADERS[name]


#środowisko tabular z booktabs; groups = numery wierszy, przed którymi idzie \midrule
def tabular(columns, header, rows, groups=()):
    lines = [f"\\begin{{tabular}}{{{columns}}}", "\\toprule"]
    lines.append(" & ".join(stacked(cell) for cell in header) + " \\\\")
    lines.append("\\midrule")
    for i, row in enumerate(rows):
        if i in groups:
            lines.append("\\midrule")
        lines.append(" & ".join(row) + " \\\\")
    lines += ["\\bottomrule", "\\end{tabular}"]
    return "\n".join(lines) + "\n"


def save(folder, name, text, note=""):
    path = os.path.join(folder, f"{name}.tex")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(HEADER)
        if note:
            handle.write("".join(f"% {line}\n" for line in note.splitlines()))
        handle.write(text)
    print("zapisano", os.path.relpath(path, REPO))


def stats_csv(variant, name):
    return pd.read_csv(os.path.join(RESULTS, "stats", variant, f"{name}.csv"))


#nazwa wariantu w nazwie pliku (bez "+")
def slug(variant):
    return variant.replace("+", "_")


def variant_names(variant):
    return VARIANTS.get(variant, variant)


#---------------------------------------------------------------- 1. zbiory źródłowe

#zbiór źródłowy tak jak w run_experiments.load_source, ale tylko z kolumnami potrzebnymi do liczności
#(bez cech okienkowych, które na liczności nie wpływają).
def load_source_columns(names):
    parts = []
    for name in names:
        flows = pd.read_parquet(os.path.join(FLOWS, f"{name}.parquet"),
                                columns=["bidirectional_first_seen_ms", "attack_type", "recording"])
        flows["source"] = name
        flows["recording"] = name + "/" + flows["recording"].astype(str)
        parts.append(flows)
    return pd.concat(parts, ignore_index=True)


def source_tables(folder):
    import run_experiments as rx  #te same funkcje podziału i próbki co w treningu (importuje Kerasa)

    full = load_source_columns(list(SOURCES))
    counts = full.groupby(["attack_type", "source"]).size().unstack(fill_value=0)
    rows = []
    for name in SOURCE_CLASSES + NOT_USED:
        rows.append([CLASS_NAMES[name]] + [integer(counts.loc[name, s]) if name in counts.index else "0"
                                           for s in SOURCES])
    rows.append(["razem"] + [integer(counts[s].sum()) for s in SOURCES])
    save(folder, "zbiory_klasy",
         tabular("lrr", ["Klasa", "CIC-IDS2017\n(4 dni)", "GeNIS"], rows,
                 groups=(len(SOURCE_CLASSES), len(rows) - 1)),
         "liczba przepływów każdej klasy po etykietowaniu (data/flows/cic.parquet i genis.parquet)")

    #próbka: S0 = pierwsze 70% każdego fragmentu (nagranie, klasa), S1 = cały zbiór; w obu walidacja =
    #ostatnie 15% każdego fragmentu części treningowej,
    #z każdej pary (źródło, klasa) najwyżej FLOWS_PER_CLASS przepływów
    source = full[~full["attack_type"].isin(rx.NOT_USED)].reset_index(drop=True)
    parts = {"S0": rx.split_in_time(source, rx.TRAINING_SHARE_S0)[0], "S1": source}
    rows = []
    for name in SOURCES:
        for scenario, flows in parts.items():
            _, sample, validation = rx.split_and_sample(flows)
            for part, table in (("trening", sample), ("walidacja", validation)):
                table = table[table["source"] == name]["attack_type"].value_counts()
                rows.append([VARIANTS.get(name, SOURCES[name]), scenario, part]  #krótko: CIC, GeNIS
                            + [integer(table.get(c, 0)) for c in SOURCE_CLASSES])
    header = ["Zbiór", "Scen.", "Część"] + [class_header(c) for c in SOURCE_CLASSES]
    save(folder, "probka", tabular("lll" + "r" * len(SOURCE_CLASSES), header, rows, groups=(4,)),
         f"próbka do treningu i walidacji: najwyżej {rx.FLOWS_PER_CLASS} przepływów na parę (źródło, klasa);\n"
         "wariant CIC używa wierszy CIC-IDS2017, wariant CIC + GeNIS obu zbiorów")


#---------------------------------------------------------------- 2. sesje z Mininetu

#ostatni przebieg każdej sesji w logu record_all.sh: parametry z linii startu, ataki wykonane
#i zaplanowane, największa przerwa między pakietami i rozmiar pcap.
def session_log(path):
    text = open(path, encoding="utf-8").read()
    info = {}
    for name in SESSIONS:
        starts = [m.start() for m in re.finditer(rf"^== {name} start", text, re.M)]
        if not starts:
            continue
        block = text[starts[-1]:]
        end = re.search(rf"^== {name} koniec.*pcap (\d+) MB", block, re.M)
        block = block[:end.end()] if end else block
        head = re.search(r"start .*?, (\d+) s, godzina (\d+), ziarno (\d+)", block)
        done = re.search(r"ataki: (\d+) z (\d+) zaplanowanych", block)
        gap = re.search(r"największa przerwa między pakietami: ([\d.]+) s", block)
        info[name] = {"duration": int(head.group(1)), "hour": int(head.group(2)), "seed": int(head.group(3)),
                      "done": int(done.group(1)), "planned": int(done.group(2)),
                      "gap": float(gap.group(1)), "pcap_mb": int(end.group(1)) if end else None}
    return info


def session_tables(folder, sessions_dir):
    from window_features import add_window_features
    from baseline_model import assessed

    log = session_log(os.path.join(sessions_dir, "log.txt"))
    flows = {s: pd.read_parquet(os.path.join(FLOWS, f"{s}.parquet")) for s in SESSIONS}
    truth = {}
    for s in SESSIONS:
        with open(os.path.join(sessions_dir, s, "ground_truth.jsonl"), encoding="utf-8") as handle:
            truth[s] = pd.Series([json.loads(line)["type"] for line in handle if line.strip()]).value_counts()

    rows = []
    for s in SESSIONS:
        f, info = flows[s], log[s]
        used = f[~f["attack_type"].isin(NOT_USED)]
        planned = str(info["done"]) if info["done"] == info["planned"] else f"{info['done']} z {info['planned']}"
        rows.append([s, f"{info['duration'] // 3600}~h", f"{info['hour']}:00", str(info["seed"]),
                     integer(len(f)), percent((used["label"] == 1).mean()), planned,
                     str(info["pcap_mb"]), number(info["gap"], 1)])
    header = ["Sesja", "Czas", "Start\nkrzywej", "Ziarno", "Przepływy", "Udział\nataków", "Ataki",
              "PCAP\n[MB]", "Przerwa\n[s]"]
    save(folder, "sesje", tabular("lrrrrrrrr", header, rows, groups=(1,)),
         "udział ataków liczony bez klasy attempted; przerwa: najdłuższa przerwa między pakietami w nagraniu;\n"
         "'x z y': ataki wykonane z zaplanowanych\n"
         "(atak, który nie zmieściłby się przed końcem sesji, nie startuje)")

    counts = pd.DataFrame({s: flows[s]["attack_type"].value_counts() for s in SESSIONS}).fillna(0)
    test = counts[TEST_SESSIONS].sum(axis=1)
    rows = []
    for name in ["normal"] + ATTACKS + ["attempted"]:
        values = counts.loc[name] if name in counts.index else pd.Series(0, index=SESSIONS)
        rows.append([CLASS_NAMES[name]] + [integer(values[s]) for s in SESSIONS]
                    + ["--" if name == "attempted" else integer(test.get(name, 0))])
    rows.append(["razem"] + [integer(counts[s].sum()) for s in SESSIONS]
                + [integer(test.drop("attempted", errors="ignore").sum())])
    save(folder, "sklad_klas", tabular("l" + "r" * 8, ["Klasa"] + SESSIONS + ["Test\nM1--M6"], rows,
                                       groups=(len(rows) - 1,)),
         "liczba przepływów każdej klasy; ostatnia kolumna: zbiór testowy M1-M6 bez attempted")

    occurrences = pd.DataFrame(truth).reindex(columns=SESSIONS).fillna(0)
    rows = []
    for name in ATTACKS:
        values = occurrences.loc[name] if name in occurrences.index else pd.Series(0, index=SESSIONS)
        rows.append([CLASS_NAMES[name]] + [integer(values[s]) for s in SESSIONS]
                    + [integer(values[TEST_SESSIONS].sum())])
    rows.append(["razem"] + [integer(occurrences[s].sum()) for s in SESSIONS]
                + [integer(occurrences[TEST_SESSIONS].sum().sum())])
    save(folder, "wystapienia_atakow",
         tabular("l" + "r" * 8, ["Atak"] + SESSIONS + ["M1--M6"], rows, groups=(len(rows) - 1,)),
         "liczba wystąpień ataków w sesjach (ground_truth.jsonl)")

    #mediany cech kontekstu hosta (okno 60 s) w każdej klasie, przepływy testowe M1-M6 razem;
    #cechy liczone na pełnej sesji (z attempted), tak jak w run_experiments.load_session
    parts = []
    for s in TEST_SESSIONS:
        full = add_window_features(flows[s].copy())
        parts.append(full[~full["attack_type"].isin(NOT_USED)])
    test_flows = pd.concat(parts, ignore_index=True)
    group = test_flows["attack_type"].map(CLASS_NAMES)
    group[(test_flows["attack_type"] == "normal") & (test_flows["src_ip"] == IOT_IP)] = "heartbeat IoT"
    rows = []
    for name in [CLASS_NAMES["normal"], "heartbeat IoT"] + [CLASS_NAMES[a] for a in ATTACKS]:
        g = test_flows[group == name]
        cv = g["host_dst_gap_cv"]
        rated = cv[assessed(cv)]
        rows.append([name, integer(len(g)), number(g["host_flows_60s"].median(), 0),
                     number(g["host_destinations_60s"].median(), 0), number(g["host_ports_60s"].median(), 0),
                     number(g["host_rst_share_60s"].median(), 2), percent(len(rated) / len(g)),
                     number(rated.median(), 3) if len(rated) else "--"])
    header = ["Ruch", "Przepływy", "Przepływy\n/ 60~s", "Cele\n/ 60~s", "Porty\n/ 60~s", "Udział\nRST",
              "Z oceną\nCV", "Mediana\nCV"]
    save(folder, "cechy_kontekstu", tabular("lrrrrrrr", header, rows, groups=(2,)),
         "mediany cech kontekstu hosta, przepływy testowe M1-M6 razem; ruch normalny bez heartbeatu IoT;\n"
         "CV (regularność odstępów do jednego celu) oceniony, gdy 0 < CV < 1 (baseline_model.assessed);\n"
         "'Z oceną CV': odsetek przepływów z ocenioną regularnością, 'Mediana CV': wśród nich")


#---------------------------------------------------------------- 3. wyniki

def metrics_tables(folder, variant):
    summary = stats_csv(variant, "summary").set_index(["scenario", "model"])
    rows = []
    for model in MODELS:
        for scenario in ("S1", "S2"):
            r = summary.loc[(scenario, model)]
            rows.append([model, scenario] + [mean_ci(r[m], r[f"{m}_ci95"])
                                             for m in ("recall", "fpr", "fpr_iot", "roc_auc", "f1")])
    header = ["Model", "Scen.", "Recall", "FPR", "FPR IoT", "AUC-ROC", "F1\n(pomocniczo)"]
    save(folder, f"metryki_{slug(variant)}", tabular("llccccc", header, rows, groups=(2, 4, 6)),
         f"wariant {variant_names(variant)}: średnia +/- 95% CI po sesjach M1-M6 "
         f"(results/stats/{variant}/summary.csv)")

    attacks = stats_csv(variant, "recall_per_attack").set_index(["scenario", "model", "attack"])["recall"]
    rows = [[model, scenario] + [number(attacks.get((scenario, model, a)), 2) for a in ATTACKS]
            for model in MODELS for scenario in ("S1", "S2")]
    save(folder, f"recall_ataki_{slug(variant)}",
         tabular("ll" + "c" * len(ATTACKS), ["Model", "Scen."] + [class_header(a) for a in ATTACKS], rows,
                 groups=(2, 4, 6)),
         f"wariant {variant_names(variant)}: recall każdego ataku, średnia po sesjach M1-M6")


#AUC-ROC każdego ataku i recall każdego ataku przy FPR 1% (uporządkowanie wyników niezależnie od progu)
def ranking_tables(folder, variant):
    summary = stats_csv(variant, "summary").set_index(["scenario", "model"])
    auc = stats_csv(variant, "auc_per_attack").set_index(["scenario", "model", "attack"])["auc"]
    header = ["Model", "Scen.", "Wszystkie\nataki"] + [class_header(a) for a in ATTACKS]
    rows = [[model, scenario, number(summary.loc[(scenario, model), "roc_auc"], 2)]
            + [number(auc.get((scenario, model, a)), 2) for a in ATTACKS]
            for model in MODELS for scenario in ("S1", "S2")]
    columns = "ll" + "c" * (len(ATTACKS) + 1)
    save(folder, f"auc_ataki_{slug(variant)}", tabular(columns, header, rows, groups=(2, 4, 6)),
         f"wariant {variant_names(variant)}: AUC-ROC każdego ataku (atak wobec ruchu normalnego sesji), średnia po\n"
         "sesjach M1-M6 (auc_per_attack.csv); wszystkie ataki: średnia po sesjach AUC-ROC na wszystkich\n"
         "przepływach sesji (summary.csv)")

    #rzeczywisty FPR osobną kolumną: przy remisach wyników (baseline, RF) wychodzi poniżej 1%
    recall = stats_csv(variant, "recall_at_fpr1").set_index(["scenario", "model", "attack"])
    rows = [[model, scenario, number(recall.loc[(scenario, model, "wszystkie"), "fpr"])]
            + [number(recall["recall"].get((scenario, model, a)), 2) for a in ["wszystkie"] + ATTACKS]
            for model in MODELS for scenario in ("S1", "S2")]
    save(folder, f"recall_fpr1_{slug(variant)}",
         tabular("ll" + "c" * (len(ATTACKS) + 2), header[:2] + ["FPR\n(rzecz.)"] + header[2:], rows,
                 groups=(2, 4, 6)),
         f"wariant {variant_names(variant)}: recall przy FPR najwyżej 1% (próg dobrany w każdej sesji na jej\n"
         "ruchu normalnym, więc ocena uporządkowania wyników, a nie punkt pracy), średnia po sesjach M1-M6\n"
         "(recall_at_fpr1.csv); FPR (rzecz.): średni FPR przy tym progu, niższy od 1% przy remisach wyników")


def s0_table(folder):
    rows = []
    for variant in VARIANTS:
        s0 = stats_csv(variant, "s0")
        for test, part in s0.groupby("test", sort=False):
            for model in MODELS:
                r = part[part["model"] == model].iloc[0]
                rows.append([variant_names(variant), SOURCES.get(test.replace("_test", ""), test), model]
                            + [number(r[m]) for m in ("recall", "fpr", "roc_auc", "f1")])
    groups = tuple(range(len(MODELS), len(rows), len(MODELS)))
    save(folder, "s0", tabular("lllcccc", ["Wariant", "Test", "Model", "Recall", "FPR", "AUC-ROC", "F1"],
                               rows, groups=groups),
         "S0: test na ostatnich 30% każdego fragmentu (nagranie, klasa) zbioru źródłowego,\n"
         "osobno dla każdego źródła")


def comparison_tables(folder):
    rows = []
    tables = {v: stats_csv(v, "s2_vs_s1").set_index("model") for v in VARIANTS}
    for model in MODELS:
        row = [model]
        for variant in VARIANTS:
            r = tables[variant].loc[model]
            n = int(r["sessions"])
            ties = f", remis w {int(r['recall_equal_in'])}" if r["recall_equal_in"] else ""
            fpr_ties = f", remis w {int(r['fpr_equal_in'])}" if r["fpr_equal_in"] else ""
            row += [f"{signed(r['fpr_mean_difference'])} ({int(r['fpr_lower_in'])} z {n}{fpr_ties})",
                    f"{signed(r['recall_mean_difference'])} ({int(r['recall_higher_in'])} z {n}{ties})"]
        rows.append(row)
    header = ["Model"] + [f"{variant_names(v)}\n{m}" for v in VARIANTS for m in ("FPR", "recall")]
    save(folder, "s2_wobec_s1", tabular("lllll", header, rows),
         "średnia różnica S2 - S1 w tej samej sesji; w nawiasie: w ilu sesjach S2 ma niższy FPR / wyższy recall")

    rows = []
    for variant in VARIANTS:
        points = stats_csv(variant, "roc_points").set_index(["scenario", "model"])
        for model in MODELS:
            row = [variant_names(variant), model]
            for scenario in ("S1", "S2"):
                p = points.loc[(scenario, model)]
                row += [f"{number(p['fpr'])} / {number(p['tpr'])}", number(p["roc_auc"])]
            rows.append(row)
    header = ["Wariant", "Model", "S1\nFPR / TPR", "S1\nAUC", "S2\nFPR / TPR", "S2\nAUC"]
    save(folder, "punkt_pracy", tabular("llcccc", header, rows, groups=(len(MODELS),)),
         "punkt pracy (próg z walidacji) na krzywej ROC, przepływy M1-M6 razem (roc_points.csv)")

    rows = []
    tables = {v: stats_csv(v, "macro_recall").set_index(["scenario", "model"]) for v in VARIANTS}
    for model in MODELS:
        for scenario in ("S1", "S2"):
            row = [model, scenario]
            for variant in VARIANTS:
                r = tables[variant].loc[(scenario, model)]
                row += [mean_ci(r["macro_recall"], r["macro_recall_ci95"]),
                        mean_ci(r["macro_recall_known"], r["macro_recall_known_ci95"])]
            rows.append(row)
    header = ["Model", "Scen."] + [f"{variant_names(v)}\n{a}" for v in VARIANTS for a in ("5 ataków", "A1--A4")]
    save(folder, "sredni_recall", tabular("llcccc", header, rows, groups=(2, 4, 6)),
         "średni recall po atakach (każdy atak z tą samą wagą), średnia +/- 95% CI po sesjach M1-M6")


def rf_f1_table(folder):
    tables = {v: stats_csv(v, "rf_class_f1") for v in VARIANTS}
    first = tables["cic"]
    classes = list(first[first["scenario"] == "S1"]["class"])
    rows = []
    for name in classes:
        flows = first[(first["scenario"] == "S1") & (first["class"] == name)]["flows"].iloc[0]
        macro = name.startswith("macro")
        label = "macro-F1 bez Z1" if macro and "bez" in name else CLASS_NAMES.get(name, name)
        row = [label, "" if macro or pd.isna(flows) else integer(flows)]
        for variant in VARIANTS:
            t = tables[variant].set_index(["scenario", "class"])["f1"]
            row += [number(t.get((s, name))) for s in ("S1", "S2")]
        rows.append(row)
    header = ["Klasa", "Przepływy"] + [f"{variant_names(v)}\n{s}" for v in VARIANTS for s in ("S1", "S2")]
    first_macro = next(i for i, name in enumerate(classes) if name.startswith("macro"))
    save(folder, "rf_f1_klasy", tabular("lrcccc", header, rows, groups=(first_macro,)),
         "F1 każdej klasy dla RF (macierz 6 x 6 zsumowana po M1-M6, rf_class_f1.csv);\n"
         "klasy c2_beaconing nie ma w treningu, więc jej F1 = 0 z definicji")


#liczba przebiegów i epoka wag FT w S1 i S2 (metrics.csv; w S2 ta sama w każdej sesji)
def ft_epochs(variant):
    result = {}
    for folder, scenario in (("S0_S1", "S1"), ("S2", "S2")):
        m = pd.read_csv(os.path.join(RESULTS, folder, variant, "metrics.csv"))
        m = m[(m["scenario"] == scenario) & (m["model"] == "FT")]
        result[scenario] = (int(m["epochs_run"].iloc[0]), int(m["best_epoch"].iloc[0]))
    return result


def cost_table(folder):
    rows = []
    for variant in VARIANTS:
        cost = stats_csv(variant, "cost").set_index(["scenario", "model"])
        epochs = ft_epochs(variant)
        for model in MODELS:
            row = [variant_names(variant), model]
            for scenario in ("S1", "S2"):
                text = seconds(cost.loc[(scenario, model), "train_seconds"])
                if model == "FT":
                    text += " ({} / {})".format(*epochs[scenario])
                row.append(text)
            row += [per_second(cost.loc[(s, model), "flows_per_second"]) for s in ("S1", "S2")]
            rows.append(row)
    header = ["Wariant", "Model", "Trening\nS1 [s]", "Adaptacja\nS2 [s]", "Przepływy/s\nS1", "Przepływy/s\nS2"]
    save(folder, "koszt", tabular("llrrrr", header, rows, groups=(len(MODELS),)),
         "trening: jeden model na wariant i scenariusz, przepustowość: średnio na sesję (cost.csv);\n"
         "FT w nawiasie: liczba przebiegów / epoka, z której są wagi")


def threshold_table(folder, models=("RF", "FT")):
    rows = []
    for variant in VARIANTS:
        quantiles = stats_csv(variant, "score_quantiles").set_index(["scenario", "model", "group"]).sort_index()
        summary = stats_csv(variant, "summary").set_index(["scenario", "model"])
        attacks = stats_csv(variant, "recall_per_attack").set_index(["scenario", "model", "attack"])["recall"]
        for model in models:
            places = 3 if model == "RF" else 4
            for scenario in ("S1", "S2"):
                q = quantiles.loc[(scenario, model)]
                iot = summary.loc[(scenario, model), "fpr_iot"]
                z1 = attacks.get((scenario, model, "c2_beaconing"))
                rows.append([variant_names(variant), scenario, model,
                             number(q.loc["ruch normalny", "threshold"], places),
                             number(q.loc["ruch normalny", "q50"], places),
                             f"{number(q.loc['heartbeat IoT', 'q50'], places)} ({number(iot, 2)})",
                             f"{number(q.loc['Z1 c2_beaconing', 'q50'], places)} ({number(z1, 2)})"])
    header = ["Wariant", "Scen.", "Model", "Próg", "Ruch\nnormalny", "Heartbeat\nIoT", "Z1\nbeaconing"]
    save(folder, "wyniki_wobec_progu", tabular("lllcccc", header, rows, groups=tuple(range(2, len(rows), 2))),
         "mediany wyników modelu (score_quantiles.csv, przepływy M1-M6 razem); w nawiasie odsetek nad progiem:\n"
         "FPR IoT i recall Z1 jako średnia po sesjach (summary.csv, recall_per_attack.csv)")


def realism_table(folder):
    realism = stats_csv("cic", "traffic_realism")
    names = {0: "sesje użytkowników (odstęp / średnia hosta)", 1: "heartbeat IoT"}
    rows = [[names.get(i, r["traffic"]), integer(r["gaps"]), number(r["cv"]), number(r["ks_d"])]
            for i, r in realism.iterrows()]
    save(folder, "realizm", tabular("lrcc", ["Ruch", "Odstępy", "CV", "D (K-S,\nwykładniczy)"], rows),
         "odstępy między startami sesji użytkowników i heartbeatu IoT w M1-M6 (traffic_realism.csv);\n"
         "bez odstępów nachodzących na atak z danego hosta (jego ruch normalny jest wtedy wstrzymany)")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=os.path.join(REPO, "praca", "tabele"), help="katalog na pliki .tex")
    parser.add_argument("--sessions-dir", default="/root/sessions",
                        help="katalog sesji z record_all.sh (log.txt, ground_truth.jsonl)")
    parser.add_argument("--only", choices=["sources", "sessions", "results"], help="tylko jedna grupa tabel")
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)

    if args.only in (None, "results"):
        for variant in VARIANTS:
            metrics_tables(args.out, variant)
            ranking_tables(args.out, variant)
        s0_table(args.out)
        comparison_tables(args.out)
        rf_f1_table(args.out)
        cost_table(args.out)
        threshold_table(args.out)
        realism_table(args.out)
    if args.only in (None, "sessions"):
        if os.path.exists(os.path.join(args.sessions_dir, "log.txt")):
            session_tables(args.out, args.sessions_dir)
        else:
            print(f"brak {args.sessions_dir}/log.txt: pomijam tabele sesji")
    if args.only in (None, "sources"):
        source_tables(args.out)
    print("tabele:", len(glob.glob(os.path.join(args.out, "*.tex"))))


if __name__ == "__main__":
    main()
