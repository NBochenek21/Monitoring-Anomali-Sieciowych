#!/usr/bin/env python3
"""Dashboard alertów w trybie replay.

Odtwarza nagraną sesję z Mininetu w przyspieszonym tempie: co sekundę "zegar" sesji przesuwa się
o tyle sekund, ile wynosi tempo, a przepływy, które zdążyły się zacząć, trafiają do modeli.
Alarm = wynik modelu powyżej progu (predykcje i progi z models/run_experiments.py dla scenariusza S1
i z models/run_s2.py dla S2; scenariusz wybiera się w pasku bocznym). Alarmy wszystkich modeli trafiają
do dziennika SQLite (alerts.sqlite w katalogu bieżącego biegu), a "Od nowa" go czyści. Widoki liczą alarmy
z przepływów w pamięci; baza jest zapisem alarmów (np. do przejrzenia po odtworzeniu).

    /root/venvs/ft/bin/python app/dashboard.py --predictions results/raw/S1_cic_M1 \
        --ground-truth /root/sessions/M1/ground_truth.jsonl
    potem w przeglądarce: http://localhost:8050

Zakładka „Porównanie” czyta wyniki stats/summarize.py z results/stats/<wariant>/.
"""
import argparse
import json
import os
import sqlite3
import sys

import numpy as np
import pandas as pd
import plotly.graph_objects as go
from dash import Dash, Input, Output, State, ctx, dash_table, dcc, html, no_update
from dash.dash_table.Format import Format, Scheme

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "models"))
import classic_models  # noqa: E402

# kolory panelu (te same co w assets/style.css): jasny motyw, kolor tylko tam, gdzie coś znaczy
BG = "#f4f6f9"
CARD = "#ffffff"
RAISED = "#eef1f5"
HEADER = "#f7f8fa"
BORDER = "#d9dee5"
GRID = "#edf0f4"
TEXT = "#1f2937"
MUTED = "#6b7280"
NEUTRAL = "#9ca3af"
RED = "#dc2626"
GREEN = "#16a34a"
YELLOW = "#d97706"
# każdy model ma jeden kolor na wszystkich wykresach; bez czerwieni, żółci i zieleni (mają znaczenie)
MODEL_COLORS = {"baseline": "#9ca3af", "IF": "#3b6fd6", "RF": "#8b5cf6", "FT": "#1f2937"}
SANS = "Segoe UI, Arial, sans-serif"
MONO = "Roboto Mono, Consolas, monospace"
SERIF = "'Times New Roman', Times, serif"  # czcionka wykresów taka jak tekst pracy (pakiet times)
# style linii modeli: na wydruku czarno-białym kolory IF i RF są nie do odróżnienia
MODEL_DASH = {"baseline": "dot", "IF": "dashdot", "RF": "solid", "FT": "dash"}
# eksport przyciskiem aparatu: PNG w 4-krotnej rozdzielczości (ok. 2800 px szerokości), do druku w pracy
EXPORT_CONFIG = {"displaylogo": False, "toImageButtonOptions": {"format": "png", "scale": 4}}


# liczba z przecinkiem dziesiętnym (polska notacja), dla tekstów składanych w Pythonie
def pl(text):
    return text.replace(".", ",")

table_header = {"backgroundColor": HEADER, "color": MUTED, "fontWeight": "600",
                "border": f"1px solid {MUTED}", "padding": "8px 12px", "textAlign": "left",
                "fontFamily": SANS, "fontSize": "12px"}
table_cell = {"backgroundColor": CARD, "color": TEXT, "border": f"1px solid {BORDER}",
              "padding": "6px 12px", "textAlign": "left"}

parser = argparse.ArgumentParser()
parser.add_argument("--predictions", required=True, help="katalog z predictions.parquet i thresholds.json")
parser.add_argument("--ground-truth", required=True, help="ground_truth.jsonl sesji")
args = parser.parse_args()

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "results", "raw")       # predykcje per (scenariusz, wariant, sesja)
SCENARIO_LABELS = {"S1": "S1 - bez adaptacji", "S2": "S2 - po adaptacji na M0"}
STATS_ROOT = os.path.join(HERE, "..", "results", "stats")  # wyniki stats/summarize.py per wariant
SESSIONS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(args.ground_truth)))  # np. /root/sessions


# Scenariusze, warianty i sesje z folderów results/raw/<scenariusz>_<wariant>_<sesja> (do przełączników).
# Sesja bez ground truth w katalogu nagrań (np. stara sesja testowa T_check) nie trafia do listy,
# bo replay potrzebuje okien ataków.
def available_runs():
    scenarios, variants, sessions = [], [], []
    if os.path.isdir(RAW):
        for name in sorted(os.listdir(RAW)):
            if name[:3] in ("S1_", "S2_") and os.path.isdir(os.path.join(RAW, name)):
                variant, session = name[3:].split("_", 1)  # wariant bez podkreślnika, reszta to sesja (np. M1)
                if not os.path.exists(ground_truth_for(session)):
                    continue
                for value, pool in ((name[:2], scenarios), (variant, variants), (session, sessions)):
                    if value not in pool:
                        pool.append(value)
    return scenarios, variants, sessions


# Napis nad widokami: który bieg jest odtwarzany (scenariusz, na czym uczone modele, sesja testowa).
def run_label(scenario, variant, session):
    return (f"Odtwarzany bieg: scenariusz {SCENARIO_LABELS.get(scenario, scenario)} | "
            f"modele uczone na: {variant} | sesja testowa: {session}")


# Ground truth sesji z katalogu nagrań (obok sesji podanej w --ground-truth, np. /root/sessions/M2/).
def ground_truth_for(session):
    return os.path.join(SESSIONS_DIR, session, "ground_truth.jsonl")


# Folder biegu replay w results/raw: <scenariusz>_<wariant>_<sesja>.
def run_folder(scenario, variant, session):
    return os.path.join(RAW, f"{scenario}_{variant}_{session}")


# Dane jednego biegu replay: przepływy z predykcjami, progi, okna ataków i długość sesji.
# folder i ground_truth podaje tylko pierwszy bieg (z argumentów); przełącznik bierze je z nazw.
# t = chwila KOŃCA przepływu od początku sesji: wtedy przepływ jest eksportowany i model może dać
# wynik, więc w replayu przepływ (i alarm) pojawia się dopiero wtedy. t_start = start przepływu,
# według którego przepływ należy do okna ataku. Starsze predykcje bez kolumny końca: t = start.
def load_run(scenario, variant, session, folder=None, ground_truth=None):
    folder = folder or run_folder(scenario, variant, session)
    flows = pd.read_parquet(os.path.join(folder, "predictions.parquet"))
    with open(os.path.join(folder, "thresholds.json")) as file:
        thresholds = json.load(file)
    with open(ground_truth or ground_truth_for(session)) as file:
        attacks = [json.loads(line) for line in file if line.strip()]
    session_start = flows["bidirectional_first_seen_ms"].min() / 1000
    flows["t_start"] = flows["bidirectional_first_seen_ms"] / 1000 - session_start  # czas od początku sesji [s]
    end_column = "bidirectional_last_seen_ms"
    if end_column not in flows:
        end_column = "bidirectional_first_seen_ms"
    flows["t"] = flows[end_column] / 1000 - session_start
    return flows, thresholds, attacks, session_start, flows["t"].max()


SCENARIOS, VARIANTS, SESSIONS = available_runs()
# początkowy wybór z argumentów: info.json w folderze --predictions, a bez niego nazwa folderu
# <scenariusz>_<wariant>_<sesja>; dane pierwszego biegu czytam z tego folderu, nie z kopii w results/raw
start_folder = os.path.abspath(args.predictions)
folder_name = os.path.basename(os.path.normpath(start_folder))
if folder_name[:3] in ("S1_", "S2_") and "_" in folder_name[3:]:
    name_variant, name_session = folder_name[3:].split("_", 1)
    info = {"scenario": folder_name[:2], "source": name_variant, "session": name_session}
else:
    info = {"scenario": "S1", "source": VARIANTS[0] if VARIANTS else "?", "session": folder_name}
info_path = os.path.join(start_folder, "info.json")
if os.path.exists(info_path):
    with open(info_path) as f:
        info = {"scenario": info["scenario"]} | json.load(f)  # starsze info.json nie mają pola scenario
current_scenario, current_variant, current_session = info["scenario"], info["source"], info["session"]
for value, pool in ((current_scenario, SCENARIOS), (current_variant, VARIANTS), (current_session, SESSIONS)):
    if value not in pool:
        pool.insert(0, value)
flows, thresholds, attacks, session_start, session_length = load_run(current_scenario, current_variant,
                                                                     current_session, start_folder, args.ground_truth)
models = list(thresholds.keys())


# Baza alarmów (dziennik SQLite) w folderze bieżącego biegu. Zasada: baza zawiera alarmy z przepływów
# o t <= bieżący czas suwaka. Uruchomienie i zmiana biegu tworzą plik od nowa (DELETE bez VACUUM
# zostawiał puste strony i plik rósł do 100 MB) i od razu zapisują alarmy z t <= 0, bo suwak stoi na 0.
# Widok liczy alarmy z przepływów, baza je tylko zapisuje. Aplikacja zakłada jednego użytkownika
# i jedną kartę przeglądarki (bieg i baza są wspólne dla całego procesu).
def reset_database(folder):
    global database_path
    database_path = os.path.join(folder, "alerts.sqlite")
    if os.path.exists(database_path):
        os.remove(database_path)
    with sqlite3.connect(database_path) as database:
        database.execute("CREATE TABLE alerts (model TEXT, time_s REAL, src_ip TEXT, dst_ip TEXT, "
                         "dst_port INTEGER, score REAL, attack_type TEXT)")
    save_alerts(float("-inf"), 0)


# alarmy wszystkich modeli z przepływów, które pojawiły się (skończyły) w przedziale (start, end]
def save_alerts(start, end):
    new_flows = flows[(flows["t"] > start) & (flows["t"] <= end)]
    rows = []
    for model in models:
        alerts = new_flows[new_flows[f"score_{model}"] > thresholds[model]]
        for flow in alerts.itertuples():
            rows.append((model, flow.t, flow.src_ip, flow.dst_ip, int(flow.dst_port),
                         float(getattr(flow, f"score_{model}")), flow.attack_type))
    with sqlite3.connect(database_path) as database:
        database.executemany("INSERT INTO alerts VALUES (?, ?, ?, ?, ?, ?, ?)", rows)


reset_database(start_folder)


# przy cofnięciu suwaka: usuwa z bazy alarmy późniejsze niż nowy czas
def remove_alerts_after(time):
    with sqlite3.connect(database_path) as database:
        database.execute("DELETE FROM alerts WHERE time_s > ?", (time,))


# przepływy do pokazania na wykresach i w tabeli: lista (nazwa serii, przepływy, kolor)
def chosen_flows(seen, model, show):
    is_alarm = seen[f"score_{model}"] > thresholds[model]
    is_attack = seen["label"] == 1
    hits = ("trafione alarmy", seen[is_alarm & is_attack], GREEN)
    false_alarms = ("fałszywe alarmy", seen[is_alarm & ~is_attack], YELLOW)
    if show == "hits":
        return [hits]
    if show == "false":
        return [false_alarms]
    if show == "missed":
        return [("pominięte ataki", seen[~is_alarm & is_attack], NEUTRAL)]
    if show == "flows":
        return [("przepływy ataków", seen[is_attack], RED), ("przepływy normalne", seen[~is_attack], NEUTRAL)]
    return [hits, false_alarms]


# opóźnienie detekcji = chwila pierwszego trafionego alarmu (koniec przepływu, czyli moment, w którym
# model może dać wynik) minus start ataku; przepływ należy do ataku według swojego startu
def detection_delays(seen):
    rows = []
    for attack in attacks:
        start = attack["start"] - session_start
        end = attack["end"] - session_start
        row = {"atak": attack["type"], "start [s]": round(start, 1)}
        attack_flows = seen[(seen["attack_type"] == attack["type"]) & (seen["t_start"] >= start)
                            & (seen["t_start"] <= end)]
        for name in models:
            hits = attack_flows[attack_flows[f"score_{name}"] > thresholds[name]]
            row[name] = round(hits["t"].min() - start, 1) if len(hits) else "-"
        rows.append(row)
    return rows


# kafelek KPI nad widokami: mały tytuł i duża liczba (kolor = znaczenie, np. czerwony dla alarmów)
def card(title, value, color=TEXT):
    return html.Div([
        html.Div(title, className="kpi-title"),
        html.Div(value, className="kpi-value", style={"color": color}),
    ], className="kpi")


# element sterowania z podpisem nad nim (np. „Model” + przełącznik modeli)
def control(label, element, class_name=""):
    return html.Div([html.Div(label, className="control-label"), element], className=class_name)


# Znaczniki suwaka czasu: kilka-kilkanaście podziałek, podpisy mm:ss (zamiast gęstej skali sekund).
def slider_marks(length):
    length = int(length)
    step = next(s for s in (600, 300, 120, 60, 30, 10) if length / s <= 12 or s == 10)
    return {second: f"{second // 60}:{second % 60:02d}" for second in range(0, length + 1, step)}


# wygląd jak figura w artykule: szeryfowa czcionka, ramka wokół pola (osie odbite), znaczniki do
# środka, delikatna kropkowana siatka i oprawiona legenda nad wykresem
def style_figure(fig):
    fig.update_layout(template="plotly_white", paper_bgcolor=CARD, plot_bgcolor=CARD, height=420,
                      separators=", ",  # przecinek dziesiętny i spacja tysięcy w liczbach Plotly
                      font=dict(family=SERIF, color=TEXT, size=13),
                      title=dict(x=0, xanchor="left", font=dict(size=13, color=TEXT)),
                      margin=dict(l=62, r=22, t=56, b=50), bargap=0.18,
                      legend=dict(orientation="h", x=0.5, y=1.05, xanchor="center", yanchor="bottom",
                                  font=dict(size=12), bgcolor=CARD, bordercolor=TEXT, borderwidth=1),
                      hoverlabel=dict(bgcolor=RAISED, bordercolor=BORDER, font=dict(family=MONO, color=TEXT)))
    axis = dict(showline=True, linewidth=1, linecolor=TEXT, mirror=True, zeroline=False,
                ticks="inside", tickcolor=TEXT, ticklen=5, tickwidth=1,
                gridcolor=GRID, griddash="dot", title_font=dict(size=13, family=SERIF))
    fig.update_xaxes(**axis)
    fig.update_yaxes(**axis)
    return fig


# Liczby do podpisów, liczone z wyników (po nowym biegu zmieniają się same):
#   - udział ataków w testach M1-M6 i w S0 (metrics.csv obu scenariuszy),
#   - dwie najliczniejsze klasy ataków i ich udział wśród przepływów ataków (macierz pomyłek RF, S1).
def share_notes(variant, confusion):
    tables = []
    for folder in ("S0_S1", "S2"):
        path = os.path.join(HERE, "..", "results", folder, variant, "metrics.csv")
        if os.path.exists(path):
            tables.append(pd.read_csv(path, usecols=["scenario", "attack_share"]))
    note = "udział ataków różni się między testami"
    if tables:
        shares = pd.concat(tables)
        mininet = shares[shares["scenario"].isin(["S1", "S2"])]["attack_share"]
        s0 = shares[shares["scenario"] == "S0"]["attack_share"]
        parts = []
        if len(mininet):
            parts.append(f"w M1-M6 ataki to {mininet.min():.0%}-{mininet.max():.0%} przepływów")
        if len(s0):
            parts.append(f"w S0 {s0.min():.0%}" + ("" if s0.min() == s0.max() else f"-{s0.max():.0%}"))
        if parts:
            note = ", ".join(parts)
    dominant = ""
    if confusion is not None and len(confusion):
        truth = confusion[(confusion["model"] == "RF") & (confusion["scenario"] == "S1")].groupby("true")["count"].sum()
        attack_counts = truth.drop("normal", errors="ignore")
        if attack_counts.sum() > 0:
            top = attack_counts.sort_values(ascending=False).head(2)
            dominant = f" ({' i '.join(top.index)} to {top.sum() / attack_counts.sum():.0%} przepływów ataków w M1-M6)"
    return note, dominant


# Porównanie modeli na wszystkich sesjach testowych (pliki z stats/summarize.py), dla danego wariantu.
# Kolejność jak w rozdziale z wynikami: PB1 (S0 -> S1 -> S2, krzywe ROC, stabilność między sesjami),
# PB2 (ataki, średni recall po atakach, macierz pomyłek RF, koszt), PB3 (wynik modelu a próg),
# na końcu realizm ruchu normalnego. Podpisy tylko opisują, co pokazuje rysunek; wnioski są w tekście
# pracy, bo zależą od wariantu i od biegu. Liczby w podpisach są liczone z wyników.
def comparison_page(variant):
    stats_folder = os.path.join(STATS_ROOT, variant)

    # jeden plik CSV ze statystyki albo None, gdy summarize.py jeszcze go nie policzył
    def read(name):
        path = os.path.join(stats_folder, f"{name}.csv")
        return pd.read_csv(path) if os.path.exists(path) else None

    summary, by_session = read("summary"), read("fpr_by_session")
    attack_recall, s2_vs_s1 = read("recall_per_attack"), read("s2_vs_s1")
    confusion, rf_f1, s0 = read("confusion"), read("rf_class_f1"), read("s0")
    roc_curves, roc_points, quantiles = read("roc_curves"), read("roc_points"), read("score_quantiles")
    cost, realism, gaps = read("cost"), read("traffic_realism"), read("traffic_gaps")
    macro = read("macro_recall")
    attack_share_note, dominant_note = share_notes(variant, confusion)
    if summary is None or by_session is None or attack_recall is None:
        return [html.Div(f"Brak wyników w {stats_folder}: uruchom stats/summarize.py.", className="hint")]
    model_order = list(MODEL_COLORS)  # baseline, IF, RF, FT
    order = {model: position for position, model in enumerate(model_order)}
    summary = summary.sort_values(["scenario", "model"], key=lambda c: c.map(order) if c.name == "model" else c)
    scenario_color = {"S1": NEUTRAL, "S2": TEXT}  # S1 jasny, S2 ciemny na wszystkich wykresach
    graph_config = EXPORT_CONFIG

    # tekst do tabeli: „średnia ± połowa przedziału”, sama średnia przy jednej sesji, „-” przy braku
    def with_ci(row, metric):
        mean, half_width = row[metric], row[f"{metric}_ci95"]
        if pd.isna(mean):
            return "-"
        return pl(f"{mean:.3f}" if pd.isna(half_width) else f"{mean:.3f} ± {half_width:.3f}")

    # nagłówek sekcji z linią oddzielającą, żeby każda część porównania była wyraźnie osobno
    def heading(title, subtitle=None):
        parts = [html.Div(title, style={"fontSize": "14px", "fontWeight": "600", "color": TEXT})]
        if subtitle:
            parts.append(html.Div(subtitle, style={"fontSize": "12px", "color": MUTED, "marginTop": "3px"}))
        return html.Div(parts, style={"marginTop": "28px", "marginBottom": "12px", "paddingTop": "16px",
                                      "borderTop": f"1px solid {BORDER}"})

    # te same kolumny wyśrodkowane w nagłówku i w komórkach, żeby liczba stała pod swoją etykietą
    def centered(columns):
        return [{"if": {"column_id": c}, "textAlign": "center"} for c in columns]

    def table(rows, number_columns, **extra):
        return dash_table.DataTable(data=rows, columns=[{"name": c, "id": c} for c in rows[0]],
                                    style_header=table_header, style_cell=table_cell,
                                    style_cell_conditional=centered(number_columns),
                                    style_header_conditional=centered(number_columns),
                                    style_table={"overflowX": "auto"}, **extra)

    # podpis pod figurą w stylu artykułu: "Rys. N. opis"; numery kolejno, bo część sekcji jest opcjonalna
    figure_numbers = {}

    def caption(key, text):
        figure_numbers[key] = len(figure_numbers) + 1
        return html.Div([html.B(f"Rys. {figure_numbers[key]}. "), text],
                        style={"fontSize": "12px", "color": MUTED, "fontFamily": SERIF, "lineHeight": "1.5",
                               "textAlign": "center", "margin": "8px 10px 4px"})

    # jeden wykres na całą szerokość; layout: ustawienia, które mają wygrać ze wspólnym stylem
    # (np. inne położenie legendy)
    def graph(figure, height, under=None, **layout):
        parts = [dcc.Graph(figure=style_figure(figure).update_layout(height=height, **layout), config=graph_config)]
        return html.Div(parts + ([under] if under is not None else []))

    # wykresy jeden pod drugim (większe i czytelniejsze niż obok siebie, łatwiej je też skopiować do pracy)
    def stacked(items):
        return html.Div(items, style={"display": "flex", "flexDirection": "column", "gap": "20px"})

    # --- tabela metryk (liczby wyśrodkowane, wiersze S2 wyróżnione tłem) ---
    # recall, FPR i AUC-ROC nie zależą od udziału ataków w teście; F1 zależy (w M1-M6 ataki to 84-91%)
    metric_display = {"recall": "recall", "FPR": "fpr", "AUC-ROC": "roc_auc", "F1": "f1"}
    metric_display = {label: column for label, column in metric_display.items() if column in summary.columns}
    rows = [{"scenariusz": row["scenario"], "model": row["model"], "sesje": int(row["sessions"]),
             **{label: with_ci(row, column) for label, column in metric_display.items()}}
            for _, row in summary.iterrows()]
    children = [
        heading("Skuteczność modeli - średnia po sesjach testowych",
                "Jednostka = jedna sesja. Przy jednej sesji nie ma jeszcze przedziału ufności (±). "
                "S1 = transfer wprost ze zbioru źródłowego, S2 = po adaptacji na sesji M0 (wiersze z tłem). "
                "Recall, FPR i AUC-ROC nie zależą od udziału ataków w teście; F1 zależy (ataki to 84-91% "
                "przepływów sesji), więc jest zawyżony i pomocniczy."),
        table(rows, ["sesje", *metric_display],
              style_data_conditional=[{"if": {"filter_query": '{scenariusz} = "S2"'}, "backgroundColor": RAISED}]),
    ]

    # --- PB1: S0 (ta sama domena) -> S1 (transfer) -> S2 (po adaptacji), cztery metryki ---
    s0_names = {"cic_test": "S0 (test CIC)", "genis_test": "S0 (test GeNIS)"}

    def metric_bars(column, ylabel, ymax, key, text):
        figure = go.Figure()
        series = []
        if s0 is not None and column in s0.columns:
            for position, (test, group) in enumerate(s0.groupby("test", sort=False)):
                # S0: białe słupki z ramką (drugi test S0 z kreskowaniem), żeby różniły się w druku
                series.append((s0_names.get(test, f"S0 ({test})"), group.set_index("model")[column],
                               dict(color=CARD, line=dict(color=TEXT, width=1),
                                    pattern=dict(shape="/" if position else "", fgcolor=MUTED, size=5))))
        for scenario in ["S1", "S2"]:
            group = summary[summary["scenario"] == scenario].set_index("model")[column]
            series.append((scenario, group, dict(color=scenario_color[scenario], line=dict(color=TEXT, width=1))))
        for name, values, marker in series:
            values = values.reindex(model_order)
            figure.add_bar(x=model_order, y=values, name=name, marker=marker,
                           text=["" if pd.isna(v) else pl(f"{v:.2f}") for v in values], textposition="outside",
                           textfont=dict(family=SERIF, size=10),
                           hovertemplate="%{x} " + name + ": %{y:.3f}<extra></extra>")
        figure.update_layout(barmode="group", xaxis_title="model", yaxis_title=ylabel)
        figure.update_yaxes(range=[0, ymax])
        return graph(figure, 400, caption(key, text))

    fpr_values = list(summary["fpr"]) + (list(s0["fpr"]) if s0 is not None else [])
    fpr_max = round(float(np.nanmax(fpr_values)) * 1.35 + 0.02, 2)
    children += [
        heading("Ta sama domena (S0), transfer (S1) i adaptacja (S2) - PB1",
                "S0 = test na końcówce zbioru źródłowego (punkt odniesienia), S1 i S2 = średnia po sesjach "
                "M1-M6. Recall i AUC-ROC: im wyżej, tym lepiej; FPR: im niżej, tym lepiej. AUC-ROC ocenia samo "
                "uporządkowanie wyników, bez progu; F1 jest pomocniczy."),
        stacked([
            metric_bars("recall", "recall", 1.15, "recall",
                        "Recall (odsetek wykrytych przepływów ataku): S0 na zbiorze źródłowym, S1 po przeniesieniu "
                        "do Mininetu i S2 po adaptacji na sesji M0."),
            metric_bars("fpr", "FPR", fpr_max, "fpr",
                        "Odsetek fałszywych alarmów (FPR) na ruchu normalnym w S0, S1 i S2, przy progu "
                        "wyznaczonym na walidacji (ok. 1% FPR na zbiorze, na którym model był uczony)."),
        ]),
        stacked([
            metric_bars("roc_auc", "AUC-ROC", 1.15, "auc",
                        "AUC-ROC (pole pod krzywą ROC, niezależne od progu) w S0, S1 i S2. Wysokie AUC-ROC przy "
                        "wysokim FPR oznaczałoby, że zawodzi próg, a nie samo uporządkowanie przepływów."),
            metric_bars("f1", "F1", 1.15, "f1",
                        "F1 (średnia harmoniczna precision i recall) w S0, S1 i S2. Pomocniczo: " + attack_share_note
                        + ", więc F1 nie jest porównywalny między testami."),
        ]),
    ]

    # --- PB1: krzywe ROC z punktem pracy (próg z walidacji) ---
    if roc_curves is not None and roc_points is not None:
        children.append(heading("Krzywe ROC i punkt pracy (próg)",
                                "Linia = krzywa ROC z przepływów wszystkich sesji M1-M6, kropka = punkt pracy przy "
                                "progu z walidacji. Oś FPR w skali logarytmicznej, bo w wykrywaniu włamań liczy się "
                                "zakres małego FPR; w legendzie AUC-ROC policzone z tych samych przepływów."))
        graphs = []
        for scenario in ["S1", "S2"]:
            figure = go.Figure()
            for model in model_order:
                curve = roc_curves[(roc_curves["scenario"] == scenario) & (roc_curves["model"] == model)]
                curve = curve[curve["fpr"] >= 1e-4]  # oś logarytmiczna nie pokaże FPR = 0
                point = roc_points[(roc_points["scenario"] == scenario) & (roc_points["model"] == model)]
                if curve.empty or point.empty:
                    continue
                point = point.iloc[0]
                figure.add_scatter(x=curve["fpr"], y=curve["tpr"], mode="lines", legendgroup=model,
                                   name=pl(f"{model} (AUC {point['roc_auc']:.3f})"),
                                   line=dict(color=MODEL_COLORS[model], width=2, dash=MODEL_DASH[model]),
                                   hovertemplate=model + ": FPR %{x:.4f}, TPR %{y:.3f}<extra></extra>")
                figure.add_scatter(x=[max(point["fpr"], 1e-4)], y=[point["tpr"]], mode="markers", legendgroup=model,
                                   showlegend=False, marker=dict(color=MODEL_COLORS[model], size=11,
                                                                 line=dict(color=CARD, width=1.5)),
                                   hovertemplate=f"{model}, próg: FPR {point['fpr']:.3f}, TPR {point['tpr']:.3f}"
                                                 "<extra></extra>")
            figure.update_layout(title=scenario, xaxis_title="FPR (skala logarytmiczna)", yaxis_title="TPR (recall)")
            figure.update_xaxes(type="log", range=[-4, 0], tickvals=[1e-4, 1e-3, 1e-2, 1e-1, 1],
                                ticktext=["0,0001", "0,001", "0,01", "0,1", "1"])
            figure.update_yaxes(range=[0, 1.03])
            # legenda w prawym dolnym rogu pola (tam krzywe ROC nie dochodzą), podpisy osi jako zwykłe liczby
            graphs.append(graph(figure, 460,
                                legend=dict(orientation="v", x=0.98, y=0.04, xanchor="right", yanchor="bottom",
                                            font=dict(size=11), bgcolor=CARD, bordercolor=TEXT, borderwidth=1)))
        children += [stacked(graphs),
                     caption("roc", "Krzywe ROC modeli w scenariuszach S1 (u góry) i S2 (u dołu), z przepływów "
                                    "wszystkich sesji M1-M6; kropka to punkt pracy przy progu z walidacji. "
                                    "Odległość kropki od krzywej w lewo pokazuje, ile FPR kosztuje próg "
                                    "przeniesiony z innej sieci.")]

    # --- PB1: FPR w każdej sesji (pudełko = rozrzut między sesjami, punkty = sesje) i S2 wobec S1 ---
    children.append(heading("Stabilność między sesjami (FPR)",
                            "Każdy punkt to jedna sesja testowa; pudełko pokazuje rozrzut, gdy sesji jest więcej."))
    figure = go.Figure()
    for scenario, group in by_session.groupby("scenario"):
        figure.add_box(x=group["model"], y=group["fpr"], name=scenario, boxpoints="all", pointpos=0,
                       marker=dict(size=7), line=dict(width=1), fillcolor="rgba(0,0,0,0)",
                       marker_color=scenario_color.get(scenario, TEXT), text=group["test"],
                       hovertemplate="%{text}: %{y:.3f}<extra></extra>")
    figure.update_layout(xaxis_title="model", yaxis_title="FPR", boxmode="group",
                         xaxis=dict(categoryorder="array", categoryarray=model_order))
    children += [dcc.Graph(figure=style_figure(figure), config=graph_config),
                 caption("sessions", "Rozkład FPR każdego modelu po sesjach testowych, osobno dla S1 i S2. "
                                     "Punkt = jedna sesja; przy wielu sesjach pudełko pokazuje medianę i rozrzut.")]
    if s2_vs_s1 is not None and len(s2_vs_s1):
        # remisy (ta sama wartość w S1 i S2); starsze pliki s2_vs_s1.csv nie mają tych kolumn
        def ties(row, column):
            count = row.get(column)
            return f" (remis: {int(count)})" if count is not None and not pd.isna(count) and count > 0 else ""

        rows = [{"model": row["model"],
                 "średnia różnica FPR (S2 - S1)": f"{row['fpr_mean_difference']:+.3f}",
                 "FPR niższy w sesjach": f"{int(row['fpr_lower_in'])} z {int(row['sessions'])}"
                                         + ties(row, "fpr_equal_in"),
                 "średnia różnica recall (S2 - S1)": f"{row['recall_mean_difference']:+.3f}",
                 "recall wyższy w sesjach": f"{int(row['recall_higher_in'])} z {int(row['sessions'])}"
                                            + ties(row, "recall_equal_in")}
                for _, row in s2_vs_s1.sort_values("model", key=lambda c: c.map(order)).iterrows()]
        children += [html.Div("S2 wobec S1 w tej samej sesji", style={"fontSize": "13px", "fontWeight": "600",
                                                                     "margin": "16px 0 8px"}),
                     table(rows, list(rows[0])[1:])]

    # --- PB2: heatmapa recall każdego ataku dla każdego modelu (średnia po sesjach) ---
    children.append(heading("Wykrywalność poszczególnych ataków (recall) - PB2",
                            "Jaśniej = atak częściej pomijany. Z1 = c2_beaconing to atak niewidziany w treningu."))
    graphs = []
    for scenario, group in attack_recall.groupby("scenario"):
        recall_table = group.pivot(index="model", columns="attack", values="recall").reindex(
            [m for m in model_order if m in set(group["model"])])
        figure = go.Figure(go.Heatmap(z=recall_table.values, x=list(recall_table.columns), y=list(recall_table.index),
                                      zmin=0, zmax=1, colorscale=[[0, "#f4f6f9"], [1, "#3b6fd6"]],
                                      texttemplate="%{z:.2f}", textfont=dict(family=SERIF),
                                      hovertemplate="%{y}, %{x}: %{z:.3f}<extra></extra>", xgap=2, ygap=2,
                                      colorbar=dict(thickness=10, outlinecolor=TEXT, outlinewidth=1, title="recall")))
        figure.update_layout(title=scenario, yaxis_autorange="reversed", xaxis_title="atak", yaxis_title="model")
        graphs.append(graph(figure, 340))
    children += [stacked(graphs),
                 caption("attacks", "Recall (czułość) każdego modelu dla poszczególnych ataków, uśredniony po "
                                    "sesjach, w scenariuszach S1 (u góry) i S2 (u dołu). Z1 = c2_beaconing "
                                    "jest atakiem niewidzianym w treningu.")]

    # --- PB2: średni recall po atakach (każdy atak z tą samą wagą), S1 obok S2, z 95% CI ---
    if macro is not None and len(macro):
        def macro_bars(column, title):
            figure = go.Figure()
            for scenario in ["S1", "S2"]:
                group = macro[macro["scenario"] == scenario].set_index("model").reindex(model_order)
                figure.add_bar(x=model_order, y=group[column], name=scenario,
                               marker=dict(color=scenario_color[scenario], line=dict(color=TEXT, width=1)),
                               error_y=dict(type="data", array=group[f"{column}_ci95"], color=TEXT, thickness=1),
                               # wartość w środku słupka, żeby nie nachodziła na kreskę przedziału ufności
                               text=["" if pd.isna(v) else pl(f"{v:.2f}") for v in group[column]],
                               textposition="inside", insidetextanchor="middle",
                               textfont=dict(family=SERIF, size=10, color=CARD if scenario == "S2" else TEXT),
                               hovertemplate="%{x} " + scenario + ": %{y:.3f}<extra></extra>")
            figure.update_layout(title=title, barmode="group", xaxis_title="model", yaxis_title="średni recall")
            figure.update_yaxes(range=[0, 1.15])
            return graph(figure, 380)

        children += [heading("Średni recall po atakach - PB2",
                             "Recall ogólny liczy się na przepływach, więc dominują w nim liczne klasy" + dominant_note
                             + ". Tu każdy atak ma tę samą wagę: w każdej sesji średnia "
                             "recall ataków, potem średnia po sesjach; kreska = 95% przedział ufności."),
                     stacked([macro_bars("macro_recall", "wszystkie ataki (A1-A4 i Z1)"),
                              macro_bars("macro_recall_known", "znane ataki (A1-A4)")]),
                     caption("macro", "Średni recall po atakach (każdy atak z tą samą wagą) dla wszystkich pięciu "
                                      "ataków (u góry) i czterech znanych (u dołu), S1 obok S2. Pokazuje różnice "
                                      "niewidoczne w recall ogólnym, w którym dominują liczne klasy ataków.")]

    # --- PB2: macierz pomyłek RF 6 × 6 (zsumowana po sesjach), wiersze znormalizowane do 1, i F1 per klasa ---
    rf_matrix = confusion[confusion["model"] == "RF (klasy)"] if confusion is not None else None
    if rf_matrix is not None and len(rf_matrix):
        children.append(heading("Macierz pomyłek Random Forest (6 klas)",
                                "Wiersz = prawdziwa klasa, kolumna = klasa przewidziana; liczba w komórce to "
                                "odsetek przepływów wiersza (suma po sesjach M1-M6). Kolumna c2_beaconing jest "
                                "pusta: tej klasy nie ma w treningu."))
        classes = ["normal", "port_scan", "ssh_bruteforce", "dos_slow", "http_flood", "c2_beaconing"]
        graphs = []
        for scenario, group in rf_matrix.groupby("scenario"):
            counts = group.pivot_table(index="true", columns="predicted", values="count", aggfunc="sum",
                                       fill_value=0).reindex(index=classes, columns=classes, fill_value=0)
            shares = counts.div(counts.sum(axis=1).where(lambda total: total > 0), axis=0)
            figure = go.Figure(go.Heatmap(z=shares.values, x=classes, y=classes, zmin=0, zmax=1,
                                          colorscale=[[0, "#f4f6f9"], [1, "#3b6fd6"]], texttemplate="%{z:.2f}",
                                          customdata=counts.values, textfont=dict(family=SERIF),
                                          hovertemplate="prawda %{y}, przewidziane %{x}: %{z:.3f} "
                                                        "(%{customdata} przepływów)<extra></extra>",
                                          xgap=2, ygap=2, colorbar=dict(thickness=10, title="odsetek")))
            figure.update_layout(title=scenario, yaxis_autorange="reversed",
                                 xaxis_title="klasa przewidziana", yaxis_title="prawdziwa klasa")
            graphs.append(graph(figure, 480))
        children += [stacked(graphs),
                     caption("rf", "Macierz pomyłek Random Forest (prawdziwa klasa × klasa przewidziana) w "
                                   "scenariuszach S1 i S2. Tylko RF przewiduje typ ataku; pozostałe modele dają "
                                   "decyzję alarm / brak alarmu, więc ich odpowiednikiem jest recall per atak "
                                   f"(Rys. {figure_numbers['attacks']}) i FPR (Rys. {figure_numbers['fpr']}).")]
        if rf_f1 is not None and len(rf_f1):
            pivot = rf_f1.pivot(index="class", columns="scenario", values="f1")
            flows = rf_f1.groupby("class")["flows"].first()
            names = classes + ["macro-F1", "macro-F1 (bez c2)"]
            rows = [{"klasa": name, "przepływy": f"{int(flows[name]):,}".replace(",", " ") if name in classes else "",
                     **{f"F1 {s}": pl(f"{pivot.loc[name, s]:.3f}") for s in pivot.columns}}
                    for name in names if name in pivot.index]
            children += [html.Div("F1 każdej klasy RF (z macierzy wyżej); c2_beaconing ma F1 = 0 z założenia, "
                                  "bo RF nie zna tej klasy, dlatego jest też macro-F1 bez niej",
                                  style={"fontSize": "13px", "fontWeight": "600", "margin": "16px 0 8px"}),
                         table(rows, list(rows[0])[1:],
                               style_data_conditional=[{"if": {"filter_query": '{klasa} contains "macro"'},
                                                        "backgroundColor": RAISED, "fontWeight": "600"}])]

    # --- PB2: koszt (czas treningu i przepustowość), skala logarytmiczna ---
    if cost is not None and len(cost):
        def cost_bars(column, ylabel, label, floor):
            figure = go.Figure()
            for scenario in ["S1", "S2"]:
                values = cost[cost["scenario"] == scenario].set_index("model")[column].reindex(model_order)
                figure.add_bar(x=model_order, y=values.clip(lower=floor), name=scenario,
                               marker=dict(color=scenario_color[scenario], line=dict(color=TEXT, width=1)),
                               text=[label(v) for v in values], textposition="outside",
                               textfont=dict(family=SERIF, size=10),
                               hovertemplate="%{x} " + scenario + ": %{text}<extra></extra>")
            figure.update_layout(barmode="group", xaxis_title="model", yaxis_title=ylabel)
            # zakres osi z zapasem nad najwyższym słupkiem, żeby zmieścił się jego podpis
            shown = cost[column].clip(lower=floor)
            figure.update_yaxes(type="log", dtick=1, exponentformat="power",  # tylko pełne potęgi 10
                                range=[np.log10(shown.min()) - 0.3, np.log10(shown.max()) + 0.6])
            return graph(figure, 380)

        def seconds(value):
            return pl("< 0.1 s" if value < 0.1 else f"{value:.1f} s" if value < 10 else f"{value:.0f} s")

        def per_second(value):
            return pl(f"{value / 1e6:.1f} mln") if value >= 1e6 else f"{value / 1e3:.0f} tys."

        children += [heading("Koszt: czas treningu i przepustowość - PB2",
                             "Średnio na sesję, laptop bez GPU (i7-1255U). S1 = trening na zbiorze źródłowym, "
                             "S2 = adaptacja na M0 (FT: dostrajanie wag z S1). Oś w skali logarytmicznej."),
                     stacked([cost_bars("train_seconds", "czas treningu [s]", seconds, 0.01),
                             cost_bars("flows_per_second", "przepływy / s", per_second, 1)]),
                     caption("cost", "Czas treningu albo adaptacji (u góry) i przepustowość predykcji w "
                                     "przepływach na sekundę (u dołu), S1 obok S2. Przepustowość baseline'u to "
                                     "tylko porównanie gotowych cech z progami.")]

    # --- PB3: wynik modelu a próg w grupach przepływów (kwantyle z summarize.py) ---
    if quantiles is not None and len(quantiles):
        children.append(heading("Wynik modelu a próg: ruch normalny, IoT, Z1 i znane ataki - PB3",
                                "Pudełko = kwartyle wyników, wąsy = 5. i 95. percentyl, przerywana linia = próg "
                                "(szara S1, czarna S2); alarm, gdy wynik jest nad progiem. Wszystkie sesje M1-M6 "
                                "razem. Baseline, RF i FT w skali logarytmicznej (wynik poniżej 0,0001 pokazany "
                                "jako 0,0001)."))
        groups = ["ruch normalny", "heartbeat IoT", "Z1 c2_beaconing", "znane ataki"]
        graphs = []
        for model in model_order:
            log_scale = model != "IF"
            figure = go.Figure()
            for scenario in ["S1", "S2"]:
                rows = quantiles[(quantiles["model"] == model) & (quantiles["scenario"] == scenario)]
                if rows.empty:
                    continue
                rows = rows.set_index("group").reindex(groups)
                value = (lambda name: rows[name].clip(lower=1e-4)) if log_scale else (lambda name: rows[name])
                figure.add_box(x=groups, q1=value("q25"), median=value("q50"), q3=value("q75"),
                               lowerfence=value("q05"), upperfence=value("q95"), name=scenario,
                               marker_color=scenario_color[scenario], fillcolor="rgba(0,0,0,0)", line=dict(width=1.5),
                               hoverinfo="y")
                threshold = float(rows["threshold"].dropna().iloc[0])
                line = dict(color=scenario_color[scenario], dash="dash", width=1.5)
                figure.add_hline(y=max(threshold, 1e-4) if log_scale else threshold, line=line)
                # podpis progu w legendzie (adnotacje add_hline na osi logarytmicznej trafiają w złe miejsce)
                figure.add_scatter(x=[None], y=[None], mode="lines", line=line, name=f"próg {scenario}")
            figure.update_layout(title=model, boxmode="group", xaxis_title="", yaxis_title="wynik modelu")
            if log_scale:
                figure.update_yaxes(type="log", dtick=1, exponentformat="power")  # tylko pełne potęgi 10
            graphs.append(graph(figure, 420))
        children += [stacked(graphs),
                     caption("scores", "Rozkład wyników każdego modelu w czterech grupach przepływów wobec progu, "
                                       "S1 obok S2. Pudełko Z1 przy ruchu normalnym oznacza, że model nie odróżnia "
                                       "beaconingu od zwykłego ruchu; pudełko heartbeatu IoT nad progiem to "
                                       "fałszywe alarmy na legalnej regularności.")]

    # --- realizm ruchu normalnego (do rozdziału o środowisku symulacyjnym) ---
    if gaps is not None and len(gaps):
        def realism_note(prefix):
            if realism is None:
                return ""
            row = realism[realism["traffic"].str.startswith(prefix)]
            if row.empty:
                return ""
            row = row.iloc[0]
            ks = "" if pd.isna(row["ks_d"]) else f"; D = {pl(format(row['ks_d'], '.3f'))}"
            return f" (n = {int(row['gaps'])}; CV = {pl(format(row['cv'], '.3f'))}{ks})"

        user = gaps[gaps["traffic"] == "sesje użytkowników"]["gap"]
        heartbeat = gaps[gaps["traffic"] == "heartbeat IoT"]["gap"]
        figure = go.Figure()
        figure.add_histogram(x=user[user <= 6], histnorm="probability density", xbins=dict(start=0, end=6, size=0.2),
                             name="odstępy w nagraniach", marker=dict(color=NEUTRAL, line=dict(color=TEXT, width=0.5)))
        grid = np.linspace(0, 6, 121)
        figure.add_scatter(x=grid, y=np.exp(-grid), mode="lines", name="rozkład wykładniczy (Poisson)",
                           line=dict(color=TEXT, width=2))
        figure.update_layout(title="sesje użytkowników" + realism_note("sesje"),
                             xaxis_title="odstęp / średni odstęp hosta", yaxis_title="gęstość")
        # legenda w prawym górnym rogu pola (tam histogram jest już prawie zerowy), żeby nie zasłaniała tytułu
        user_graph = graph(figure, 380,
                           legend=dict(orientation="v", x=0.98, y=0.96, xanchor="right", yanchor="top",
                                       font=dict(size=11), bgcolor=CARD, bordercolor=TEXT, borderwidth=1))
        figure = go.Figure()
        figure.add_histogram(x=heartbeat, nbinsx=40, name="heartbeat IoT",
                             marker=dict(color=NEUTRAL, line=dict(color=TEXT, width=0.5)))
        figure.update_layout(title="heartbeat IoT" + realism_note("heartbeat"), xaxis_title="odstęp [s]",
                             yaxis_title="liczba odstępów", showlegend=False)
        children += [heading("Realizm ruchu normalnego (rozdział o środowisku)",
                             "Odstępy między startami kolejnych sesji użytkownika (podzielone przez średnią hosta, "
                             "M1-M6) wobec rozkładu wykładniczego oraz odstępy heartbeatu IoT. CV = współczynnik "
                             "zmienności, D = statystyka testu Kołmogorowa-Smirnowa."),
                     stacked([user_graph, graph(figure, 380)]),
                     caption("realism", "U góry: histogram znormalizowanych odstępów między sesjami użytkowników "
                                        "na tle gęstości rozkładu wykładniczego (proces Poissona, CV = 1); odstępy "
                                        "powyżej 6 średnich pominięte na wykresie. U dołu: odstępy heartbeatu "
                                        "IoT, prawie stałe (CV bliskie 0).")]
    return children


app = Dash(__name__)
# strona bez ikony w karcie przeglądarki (domyślny szablon Dash dokłada ikonę Plotly)
app.index_string = app.index_string.replace("{%favicon%}", "<link rel=\"icon\" href=\"data:,\">")
app.title = "Detekcja anomalii - replay"

pages = {"alerts": "Alerty", "timeline": "Oś czasu", "hosts": "Hosty", "models": "Modele",
         "comparison": "Porównanie"}


# kontener jednego widoku (zakładki); switch_page pokazuje jeden, a pozostałe zwija
def page(name, children):
    return html.Div(children, id=f"page-{name}", className="panel page-body")


app.layout = html.Div([
    # pasek boczny: nazwa, opis sesji i nawigacja
    html.Aside([
        html.Div([
            html.Div("Monitoring sieci", className="brand"),
            control("scenariusz", dcc.Dropdown(
                [{"label": SCENARIO_LABELS.get(s, s), "value": s} for s in SCENARIOS],
                current_scenario, id="pick-scenario", clearable=False, className="pick")),
            control("modele uczone na", dcc.Dropdown(VARIANTS, current_variant, id="pick-variant",
                                                     clearable=False, className="pick")),
            control("sesja testowa", dcc.Dropdown(SESSIONS, current_session, id="pick-session",
                                                  clearable=False, className="pick")),
        ], className="brand-block"),
        dcc.RadioItems([{"label": label, "value": name} for name, label in pages.items()], "alerts",
                       id="page", className="nav"),
    ], className="sidebar"),

    html.Main([
        # sterowanie odtwarzaniem
        html.Div([
            control("Model", dcc.RadioItems(models, models[-1], id="model", inline=True, className="segmented")),
            control("Tempo", dcc.RadioItems([{"label": f"{s}×", "value": s} for s in [1, 5, 10, 30]], 10,
                                            id="speed", inline=True, className="segmented")),
            control("Odtwarzanie", html.Div([
                html.Button("Start", id="play", n_clicks=0, className="button play"),
                html.Button("Pauza", id="pause", n_clicks=0, className="button pause active"),
                html.Button("Od nowa", id="reset", n_clicks=0, className="button"),
            ], className="buttons")),
            control("Czas sesji", html.Div([
                html.Div(dcc.Slider(0, round(session_length), 1, value=0, id="seek", updatemode="mouseup",
                                    marks=slider_marks(session_length),
                                    allow_direct_input=False, tooltip={"placement": "bottom"}), className="seek"),
                html.Span(id="clock-label"),
            ], className="progress-row"), class_name="session-time"),
        ], className="toolbar"),

        # który bieg jest odtwarzany: widoczne na każdej zakładce z alarmami
        html.Div(run_label(current_scenario, current_variant, current_session), id="run-label",
                 style={"margin": "4px 0 10px", "padding": "8px 12px", "border": f"1px solid {BORDER}",
                        "borderLeft": f"4px solid {TEXT}", "background": CARD, "color": TEXT,
                        "fontSize": "13px", "fontWeight": "600"}),

        html.Div(id="cards", className="kpi-strip"),

        # tytuł widoku i filtr tego, co pokazują wykresy i tabela
        html.Div([
            html.H2(id="page-title"),
            html.Div(dcc.RadioItems([
                {"label": "Alarmy", "value": "alarms"},
                {"label": "Trafione", "value": "hits"},
                {"label": "Fałszywe", "value": "false"},
                {"label": "Pominięte ataki", "value": "missed"},
                {"label": "Wszystkie przepływy", "value": "flows"},
            ], "alarms", id="show", inline=True, className="segmented"), id="show-box"),
        ], className="page-header"),

        page("alerts", [
            dash_table.DataTable(
                id="alerts",
                columns=[{"name": "czas [s]", "id": "czas [s]", "type": "numeric",
                          "format": Format(precision=1, scheme=Scheme.fixed)},
                         {"name": "źródło", "id": "źródło"}, {"name": "cel", "id": "cel"},
                         {"name": "port", "id": "port", "type": "numeric"},
                         {"name": "wynik", "id": "wynik", "type": "numeric",
                          "format": Format(precision=3, scheme=Scheme.fixed)},
                         {"name": "prawda", "id": "prawda"}],
                page_size=15, sort_action="native", filter_action="native",
                style_header=table_header,
                style_cell=table_cell,
                style_filter={"backgroundColor": BG, "borderBottom": f"1px solid {BORDER}"},
                style_data_conditional=[
                    {"if": {"filter_query": '{prawda} = "normal"', "column_id": "prawda"}, "color": YELLOW},
                    {"if": {"filter_query": '{prawda} != "normal"', "column_id": "prawda"}, "color": RED},
                    {"if": {"state": "active"}, "backgroundColor": RAISED, "border": f"1px solid {MUTED}"},
                    {"if": {"state": "selected"}, "backgroundColor": RAISED, "border": f"1px solid {MUTED}"},
                ],
            ),
            html.Div("Kolumna prawda: czerwony = przepływ ataku, żółty = ruch normalny (przy alarmach to fałszywy "
                     "alarm). Filtry w kolumnach, np. port_scan w kolumnie prawda, 10.0.1.12 w kolumnie źródło "
                     "albo > 60 w kolumnie czas.", className="hint"),
        ]),
        page("timeline", [dcc.Graph(id="timeline", responsive=True, config={"displaylogo": False})]),
        page("hosts", [dcc.Graph(id="hosts", responsive=True, config={"displaylogo": False})]),
        page("models", [
            html.Div(id="metrics"),
            dcc.Graph(id="recall-per-attack", responsive=True, config={"displaylogo": False},
                      style={"marginTop": "16px"}),
        ]),
        page("comparison", comparison_page(current_variant)),
    ], className="main"),

    dcc.Interval(id="tick", interval=1000, disabled=True),
    dcc.Store(id="clock", data=0),
], className="app")


# nawigacja: widoczny jest jeden widok; filtr "pokaż" nie dotyczy widoków modeli i porównania
@app.callback(Output("page-title", "children"), Output("show-box", "style"),
              [Output(f"page-{name}", "style") for name in pages], Input("page", "value"))
def switch_page(chosen):
    show_style = {"visibility": "hidden"} if chosen in ("models", "comparison") else {}
    hidden = {"height": 0, "overflow": "hidden", "padding": 0, "border": "none", "margin": 0}
    page_styles = [{} if name == chosen else hidden for name in pages]
    return [pages[chosen], show_style] + page_styles


# zmiana scenariusza (S1/S2), wariantu (na czym uczone) albo sesji testowej: przeładuj dane replay,
# wyczyść alarmy, ustaw suwak na początek, odśwież napis o biegu i zakładkę „Porównanie”
@app.callback(Output("seek", "max"), Output("seek", "marks"),
              Output("seek", "value", allow_duplicate=True), Output("page-comparison", "children"),
              Output("run-label", "children"),
              Input("pick-scenario", "value"), Input("pick-variant", "value"), Input("pick-session", "value"),
              prevent_initial_call=True)
def switch_run(scenario, variant, session):
    # takiego biegu nie ma (np. S2 jeszcze nie policzone): zostaje poprzedni, napis mówi dlaczego
    if not os.path.isdir(run_folder(scenario, variant, session)):
        return (no_update, no_update, no_update, no_update,
                f"Brak predykcji {scenario} dla wariantu {variant} i sesji {session} "
                f"(results/raw/{scenario}_{variant}_{session}); odtwarzany jest poprzedni bieg.")
    # global: pozostałe funkcje czytają te zmienne modułu, więc podmiana tutaj działa w całej aplikacji
    global flows, thresholds, attacks, session_start, session_length, models
    try:
        loaded = load_run(scenario, variant, session)
    except (OSError, ValueError, KeyError) as error:  # np. brak ground truth albo uszkodzony plik
        return (no_update, no_update, no_update, no_update,
                f"Nie da się wczytać biegu {scenario} {variant} {session}: {error}; odtwarzany jest poprzedni bieg.")
    flows, thresholds, attacks, session_start, session_length = loaded
    models = list(thresholds.keys())
    reset_database(run_folder(scenario, variant, session))
    return (round(session_length), slider_marks(session_length), 0, comparison_page(variant),
            run_label(scenario, variant, session))


# Start / Pauza: włącza albo wyłącza zegar (dcc.Interval co 1 s) i podświetla aktywny przycisk
@app.callback(Output("tick", "disabled"), Output("play", "className"), Output("pause", "className"),
              Input("play", "n_clicks"), Input("pause", "n_clicks"), prevent_initial_call=True)
def play_or_pause(play_clicks, pause_clicks):
    if ctx.triggered_id == "play":
        return False, "button play active", "button pause"
    return True, "button play", "button pause active"


# suwak "seek" trzyma czas sesji: odtwarzanie i "Od nowa" przesuwają suwak, a użytkownik może go przesunąć sam
@app.callback(Output("seek", "value"),
              Input("tick", "n_intervals"), Input("reset", "n_clicks"),
              State("seek", "value"), State("speed", "value"), prevent_initial_call=True)
def move_clock(n_intervals, reset_clicks, seek, speed):
    if ctx.triggered_id == "reset":
        return 0
    return min(seek + speed, session_length)


# po każdej zmianie czasu baza alarmów jest uzupełniana (do przodu) albo przycinana (do tyłu), tak żeby
# zawierała alarmy z t <= suwak; alarmy z t <= 0 zapisuje już reset_database
@app.callback(Output("clock", "data"), Input("seek", "value"), State("clock", "data"))
def sync_alerts(seek, clock):
    if seek > clock:
        save_alerts(max(clock, 0), seek)
    else:
        remove_alerts_after(seek)
    return seek


# Główny callback: po każdej zmianie czasu, modelu albo filtra przelicza wszystko, co widać, na podstawie
# przepływów, które skończyły się do bieżącej chwili (seen): kafelki, tabelę alarmów, oś czasu,
# widok hostów i metryki modeli.
@app.callback(Output("cards", "children"), Output("alerts", "data"), Output("timeline", "figure"),
              Output("metrics", "children"), Output("recall-per-attack", "figure"), Output("clock-label", "children"),
              Output("hosts", "figure"), Input("clock", "data"), Input("model", "value"), Input("show", "value"))
def update(clock, model, show):
    seen = flows[flows["t"] <= clock]
    score = seen[f"score_{model}"]
    alerts = seen[score > thresholds[model]]

    detected = int((alerts["label"] == 1).sum())
    false_alarms = int((alerts["label"] == 0).sum())
    missed = int(((seen["label"] == 1) & (score <= thresholds[model])).sum())
    cards = [
        card("Przepływy", f"{len(seen)}"),
        card("Alarmy", f"{len(alerts)}", RED),
        card("Wykryte ataki", f"{detected}", GREEN),
        card("Fałszywe alarmy", f"{false_alarms}", YELLOW),
        card("Pominięte ataki", f"{missed}", MUTED),
    ]

    chosen = chosen_flows(seen, model, show)
    # do tabeli tylko 500 najnowszych wierszy (najnowsze na górze), żeby przeglądarka się nie zatykała
    newest = pd.concat([part for name, part, color in chosen]).sort_values("t", ascending=False).head(500)
    table = pd.DataFrame({
        "czas [s]": newest["t"].round(1),
        "źródło": newest["src_ip"],
        "cel": newest["dst_ip"],
        "port": newest["dst_port"],
        "wynik": newest[f"score_{model}"].round(3),
        "prawda": newest["attack_type"],
    }).to_dict("records")

    # oś czasu: alarmy w przedziałach 5 s, na tle prawdziwych okien ataków
    timeline = go.Figure()
    for attack in attacks:
        start = attack["start"] - session_start
        if start <= clock:
            timeline.add_vrect(x0=start, x1=min(attack["end"] - session_start, clock), fillcolor=RED,
                               opacity=0.12, line_width=0, annotation_text=attack["type"],
                               annotation_position="inside top left", annotation_textangle=-90,
                               annotation_font=dict(size=10, color=MUTED))
    bins = list(range(0, int(session_length) + 6, 5))
    for name, part, color in chosen:
        timeline.add_histogram(x=part["t"], xbins=dict(start=0, end=bins[-1], size=5), name=name, marker_color=color)
    timeline.update_layout(barmode="stack", title="Przepływy w czasie (czerwone tło: prawdziwe ataki)",
                           xaxis_title="czas sesji [s]", yaxis_title="liczba przepływów",
                           xaxis_range=[0, session_length])
    style_figure(timeline)

    # widok per host: liczba przepływów według hosta źródłowego
    per_host = pd.DataFrame({name: part["src_ip"].value_counts() for name, part, color in chosen}).fillna(0)
    per_host = per_host.loc[per_host.sum(axis=1).sort_values().index].tail(20)
    hosts = go.Figure()
    for name, part, color in chosen:
        hosts.add_bar(y=per_host.index, x=per_host[name], orientation="h", name=name, marker_color=color)
    hosts.update_layout(barmode="stack", title="Według hosta źródłowego (20 hostów z największą liczbą)",
                        xaxis_title="liczba przepływów", yaxis_type="category")
    style_figure(hosts)

    # metryki wszystkich modeli na tym, co już odtworzono
    rows = []
    recall_figure = go.Figure()
    for name in models:
        result = classic_models.evaluate(seen["label"].to_numpy(), seen[f"score_{name}"].to_numpy(), thresholds[name])
        rows.append({"model": name, "recall": round(result["recall"], 3), "FPR": round(result["fpr"], 3),
                     "AUC-ROC": round(result["roc_auc"], 3), "wykryte": result["tp"], "fałszywe alarmy": result["fp"]})
        per_attack = classic_models.recall_per_attack(seen["attack_type"].to_numpy(), seen[f"score_{name}"].to_numpy(),
                                                      thresholds[name])
        recall_figure.add_bar(x=list(per_attack.keys()), y=list(per_attack.values()), name=name,
                              marker_color=MODEL_COLORS.get(name))
    recall_figure.update_layout(title="Recall per atak (odtworzona część sesji)", yaxis_range=[0, 1.05],
                                barmode="group", yaxis_title="recall")
    style_figure(recall_figure)

    metrics = dash_table.DataTable(
        data=rows, columns=[{"name": c, "id": c} for c in ["model", "recall", "FPR", "AUC-ROC", "wykryte",
                                                            "fałszywe alarmy"]],
        style_header=table_header,
        style_cell=table_cell,
    )
    delays = dash_table.DataTable(
        data=detection_delays(seen), columns=[{"name": c, "id": c} for c in ["atak", "start [s]"] + models],
        style_header=table_header,
        style_cell=table_cell,
    )
    share = seen["label"].mean() if len(seen) else 0
    note = html.Div(f"Udział ataków w odtworzonej części sesji: {share:.0%}. Recall, FPR i AUC-ROC od niego nie "
                    f"zależą; precision i F1 by zależały, dlatego ich tu nie ma (F1 jest w zakładce Porównanie, "
                    f"z zastrzeżeniem).", className="hint")

    label = f"{int(clock) // 60}:{int(clock) % 60:02d} / {int(session_length) // 60}:{int(session_length) % 60:02d}"
    delay_title = html.Div("Opóźnienie detekcji [s]: od startu ataku do pierwszego trafionego alarmu, czyli do "
                           "końca pierwszego wykrytego przepływu ataku (- = jeszcze nie wykryty)",
                           className="control-label", style={"marginTop": "20px"})
    return cards, table, timeline, [metrics, note, delay_title, delays], recall_figure, label, hosts


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=False)
