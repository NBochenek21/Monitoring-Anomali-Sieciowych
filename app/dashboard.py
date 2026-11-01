#!/usr/bin/env python3
"""Dashboard alertów w trybie replay.

Odtwarza nagraną sesję z Mininetu w przyspieszonym tempie: co sekundę "zegar" sesji przesuwa się
o tyle sekund, ile wynosi tempo, a przepływy, które zdążyły się zacząć, trafiają do modeli.
Alarm = wynik modelu powyżej progu (predykcje i progi z models/run_experiments.py dla scenariusza S1
i z models/run_s2.py dla S2; scenariusz wybiera się w pasku bocznym). Alarmy wszystkich modeli trafiają
do dziennika SQLite (alerts.sqlite w katalogu bieżącego biegu), a "Od nowa" go czyści. Widoki liczą alarmy
z przepływów w pamięci; baza jest zapisem alarmów (np. do przejrzenia po odtworzeniu).

    /root/venvs/ft/bin/python app/dashboard.py --predictions results/raw/S1_cic_T_check \
        --ground-truth data/pcap/T_check/ground_truth.jsonl
    potem w przeglądarce: http://localhost:8050
"""
import argparse
import json
import os
import sqlite3
import sys

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
SERIF = "Georgia, 'Times New Roman', Times, serif"  # czcionka wykresów jak w artykule naukowym

table_header = {"backgroundColor": HEADER, "color": MUTED, "fontWeight": "600",
                "border": f"1px solid {MUTED}", "padding": "8px 12px", "textAlign": "left",
                "fontFamily": SANS, "fontSize": "12px"}
table_cell = {"backgroundColor": CARD, "color": TEXT, "border": f"1px solid {BORDER}",
              "padding": "6px 12px", "textAlign": "left"}

parser = argparse.ArgumentParser()
parser.add_argument("--predictions", required=True, help="katalog z predictions.parquet i thresholds.json")
parser.add_argument("--ground-truth", required=True, help="ground_truth.jsonl sesji")
parser.add_argument("--stats", default=None, help="katalog z wynikami stats/summarize.py "
                                                  "(domyślnie results/stats/<wariant z info.json>)")
args = parser.parse_args()

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "..", "results", "raw")       # predykcje per (scenariusz, wariant, sesja)
SCENARIO_LABELS = {"S1": "S1 - bez adaptacji", "S2": "S2 - po adaptacji na M0"}
STATS_ROOT = args.stats and os.path.dirname(args.stats) or os.path.join(HERE, "..", "results", "stats")
SESSIONS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(args.ground_truth)))  # np. /root/sessions


# Scenariusze, warianty i sesje z folderów results/raw/<scenariusz>_<wariant>_<sesja> (do przełączników).
def available_runs():
    scenarios, variants, sessions = [], [], []
    if os.path.isdir(RAW):
        for name in sorted(os.listdir(RAW)):
            if name[:3] in ("S1_", "S2_") and os.path.isdir(os.path.join(RAW, name)):
                variant, session = name[3:].split("_", 1)  # wariant bez podkreślnika, reszta to sesja (np. T_check)
                for value, pool in ((name[:2], scenarios), (variant, variants), (session, sessions)):
                    if value not in pool:
                        pool.append(value)
    return scenarios, variants, sessions


# Napis nad widokami: który bieg jest odtwarzany (scenariusz, na czym uczone modele, sesja testowa).
def run_label(scenario, variant, session):
    return (f"Odtwarzany bieg: scenariusz {SCENARIO_LABELS.get(scenario, scenario)} | "
            f"modele uczone na: {variant} | sesja testowa: {session}")


# Ground truth sesji: najpierw w katalogu nagrań, potem w data/pcap/.
def ground_truth_for(session):
    for path in (os.path.join(SESSIONS_DIR, session, "ground_truth.jsonl"),
                 os.path.join(HERE, "..", "data", "pcap", session, "ground_truth.jsonl")):
        if os.path.exists(path):
            return path
    return os.path.join(SESSIONS_DIR, session, "ground_truth.jsonl")


# Folder biegu replay w results/raw: <scenariusz>_<wariant>_<sesja>.
def run_folder(scenario, variant, session):
    return os.path.join(RAW, f"{scenario}_{variant}_{session}")


# Dane jednego biegu replay: przepływy z predykcjami, progi, okna ataków i długość sesji.
# folder i ground_truth podaje tylko pierwszy bieg (z argumentów); przełącznik bierze je z nazw.
def load_run(scenario, variant, session, folder=None, ground_truth=None):
    folder = folder or run_folder(scenario, variant, session)
    flows = pd.read_parquet(os.path.join(folder, "predictions.parquet"))
    with open(os.path.join(folder, "thresholds.json")) as file:
        thresholds = json.load(file)
    with open(ground_truth or ground_truth_for(session)) as file:
        attacks = [json.loads(line) for line in file if line.strip()]
    session_start = flows["bidirectional_first_seen_ms"].min() / 1000
    flows["t"] = flows["bidirectional_first_seen_ms"] / 1000 - session_start  # czas od początku sesji [s]
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


# Baza alarmów (dziennik SQLite) w folderze bieżącego biegu; każde uruchomienie, zmiana biegu
# i "Od nowa" zaczyna od pustej tabeli. Widok liczy alarmy z przepływów, baza je tylko zapisuje.
def reset_database(folder):
    global database_path
    database_path = os.path.join(folder, "alerts.sqlite")
    with sqlite3.connect(database_path) as database:
        database.execute("CREATE TABLE IF NOT EXISTS alerts (model TEXT, time_s REAL, src_ip TEXT, dst_ip TEXT, "
                         "dst_port INTEGER, score REAL, attack_type TEXT)")
        database.execute("DELETE FROM alerts")


reset_database(start_folder)


# alarmy wszystkich modeli z przepływów, które zaczęły się w przedziale (start, end]
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


# opóźnienie detekcji = pierwszy trafiony alarm na przepływie ataku minus start ataku
def detection_delays(seen):
    rows = []
    for attack in attacks:
        start = attack["start"] - session_start
        end = attack["end"] - session_start
        row = {"atak": attack["type"], "start [s]": round(start, 1)}
        attack_flows = seen[(seen["attack_type"] == attack["type"]) & (seen["t"] >= start) & (seen["t"] <= end)]
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


# Porównanie modeli na wszystkich sesjach testowych (pliki z stats/summarize.py), dla danego wariantu.
def comparison_page(variant):
    stats_folder = os.path.join(STATS_ROOT, variant)

    # jeden plik CSV ze statystyki albo None, gdy summarize.py jeszcze go nie policzył
    def read(name):
        path = os.path.join(stats_folder, f"{name}.csv")
        return pd.read_csv(path) if os.path.exists(path) else None

    summary, by_session = read("summary"), read("fpr_by_session")
    attack_recall, s2_vs_s1 = read("recall_per_attack"), read("s2_vs_s1")
    if summary is None:
        return [html.Div(f"Brak wyników w {stats_folder}: uruchom stats/summarize.py.", className="hint")]
    order = {model: position for position, model in enumerate(MODEL_COLORS)}  # baseline, IF, RF, FT
    summary = summary.sort_values(["scenario", "model"], key=lambda c: c.map(order) if c.name == "model" else c)

    # tekst do tabeli: „średnia ± połowa przedziału”, sama średnia przy jednej sesji, „-” przy braku
    def with_ci(row, metric):
        mean, half_width = row[metric], row[f"{metric}_ci95"]
        if pd.isna(mean):
            return "-"
        return f"{mean:.3f}" if pd.isna(half_width) else f"{mean:.3f} ± {half_width:.3f}"

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

    # podpis pod figurą w stylu artykułu: "Rys. N. opis"
    def caption(number, text):
        return html.Div([html.B(f"Rys. {number}. "), text],
                        style={"fontSize": "12px", "color": MUTED, "fontFamily": SERIF, "lineHeight": "1.5",
                               "textAlign": "center", "margin": "8px 10px 4px"})

    # --- sekcja 1: tabela metryk (liczby wyśrodkowane, wiersze S2 wyróżnione tłem) ---
    # tylko miary niezależne od udziału ataków w teście (w M1-M6 ataki to 83-90% przepływów)
    metric_display = {"recall": "recall", "FPR": "fpr", "FPR IoT": "fpr_iot"}
    number_columns = ["sesje", *metric_display]
    rows = [{"scenariusz": row["scenario"], "model": row["model"], "sesje": int(row["sessions"]),
             **{label: with_ci(row, column) for label, column in metric_display.items()}}
            for _, row in summary.iterrows()]
    children = [
        heading("Skuteczność modeli - średnia po sesjach testowych",
                "Jednostka = jedna sesja. Przy jednej sesji nie ma jeszcze przedziału ufności (±). "
                "S1 = transfer wprost ze zbioru źródłowego, S2 = po adaptacji na sesji M0 (wiersze z tłem). "
                "Recall i FPR nie zależą od udziału ataków w teście, dlatego tylko one są tu pokazane."),
        dash_table.DataTable(
            data=rows, columns=[{"name": c, "id": c} for c in rows[0]],
            style_header=table_header, style_cell=table_cell,
            style_cell_conditional=centered(number_columns), style_header_conditional=centered(number_columns),
            style_data_conditional=[{"if": {"filter_query": '{scenariusz} = "S2"'}, "backgroundColor": RAISED}],
            style_table={"overflowX": "auto"}),
    ]

    # --- sekcja 2: słupki przed/po adaptacji dla wybranych metryk (S1 obok S2) ---
    def metric_bars(column, ylabel, ymax, number, text):
        figure = go.Figure()
        for scenario in ["S1", "S2"]:
            group = summary[summary["scenario"] == scenario]
            figure.add_bar(x=group["model"], y=group[column], name=scenario,
                           marker_color=NEUTRAL if scenario == "S1" else TEXT,
                           marker_line=dict(color=TEXT, width=1),
                           text=[f"{value:.2f}" for value in group[column]], textposition="outside",
                           textfont=dict(family=SERIF), hovertemplate="%{x} " + scenario + ": %{y:.3f}<extra></extra>")
        figure.update_layout(barmode="group", xaxis_title="model", yaxis_title=ylabel,
                             xaxis=dict(categoryorder="array", categoryarray=list(MODEL_COLORS)))
        figure = style_figure(figure).update_layout(height=340)
        figure.update_yaxes(range=[0, ymax])
        return html.Div([dcc.Graph(figure=figure, config={"displaylogo": False}), caption(number, text)],
                        style={"flex": "1", "minWidth": "360px"})

    children.append(heading("Przed i po adaptacji (S1 -> S2)",
                            "Recall to odsetek wykrytych przepływów ataku - im wyżej, tym lepiej. "
                            "FPR to odsetek fałszywych alarmów na ruchu normalnym - im niżej, tym lepiej."))
    fpr_max = round(float(summary["fpr"].max()) * 1.35 + 0.02, 2)
    children.append(html.Div([
        metric_bars("recall", "recall", 1.12, 1,
                    "Recall (odsetek wykrytych przepływów ataku) każdego modelu przy transferze wprost (S1) "
                    "i po adaptacji na sesji M0 (S2)."),
        metric_bars("fpr", "FPR", fpr_max, 2,
                    "Odsetek fałszywych alarmów (FPR) na ruchu normalnym, S1 obok S2. "
                    "Adaptacja (S2) wyraźnie obniża FPR modeli RF i FT."),
    ], style={"display": "flex", "gap": "16px", "flexWrap": "wrap"}))

    # --- sekcja 3: FPR w każdej sesji (pudełko = rozrzut między sesjami, punkty = sesje) ---
    children.append(heading("Stabilność między sesjami (FPR)",
                            "Każdy punkt to jedna sesja testowa; pudełko pokazuje rozrzut, gdy sesji jest więcej."))
    figure = go.Figure()
    for scenario, group in by_session.groupby("scenario"):
        figure.add_box(x=group["model"], y=group["fpr"], name=scenario, boxpoints="all", pointpos=0,
                       marker=dict(size=7), line=dict(width=1), fillcolor="rgba(0,0,0,0)",
                       marker_color=NEUTRAL if scenario == "S1" else TEXT, text=group["test"],
                       hovertemplate="%{text}: %{y:.3f}<extra></extra>")
    figure.update_layout(xaxis_title="model", yaxis_title="FPR", boxmode="group",
                         xaxis=dict(categoryorder="array", categoryarray=list(MODEL_COLORS)))
    children.append(dcc.Graph(figure=style_figure(figure), config={"displaylogo": False}))
    children.append(caption(3, "Rozkład FPR każdego modelu po sesjach testowych, osobno dla S1 i S2. "
                               "Punkt = jedna sesja; przy wielu sesjach pudełko pokazuje medianę i rozrzut."))

    # --- sekcja 4: heatmapa recall każdego ataku dla każdego modelu (średnia po sesjach) ---
    children.append(heading("Wykrywalność poszczególnych ataków (recall)",
                            "Jaśniej = atak częściej pomijany. Z1 = c2_beaconing to atak niewidziany w treningu."))
    graphs = []
    for scenario, group in attack_recall.groupby("scenario"):
        table = group.pivot(index="model", columns="attack", values="recall").reindex(
            [m for m in MODEL_COLORS if m in set(group["model"])])
        figure = go.Figure(go.Heatmap(z=table.values, x=list(table.columns), y=list(table.index), zmin=0, zmax=1,
                                      colorscale=[[0, "#f4f6f9"], [1, "#3b6fd6"]], texttemplate="%{z:.2f}",
                                      textfont=dict(family=SERIF),
                                      hovertemplate="%{y}, %{x}: %{z:.3f}<extra></extra>", xgap=2, ygap=2,
                                      colorbar=dict(thickness=10, outlinecolor=TEXT, outlinewidth=1, title="recall")))
        figure.update_layout(title=scenario, height=300, yaxis_autorange="reversed",
                             xaxis_title="atak", yaxis_title="model")
        graphs.append(html.Div(dcc.Graph(figure=style_figure(figure).update_layout(height=300),
                                         config={"displaylogo": False}), style={"flex": "1", "minWidth": "380px"}))
    children.append(html.Div(graphs, style={"display": "flex", "gap": "16px", "flexWrap": "wrap"}))
    children.append(caption(4, "Recall (czułość) każdego modelu dla poszczególnych ataków, uśredniony po sesjach, "
                               "w scenariuszach S1 (po lewej) i S2 (po prawej). Z1 = c2_beaconing jest atakiem "
                               "niewidzianym w treningu."))

    # --- sekcja 5: podsumowanie, czy adaptacja pomaga ---
    if s2_vs_s1 is not None and len(s2_vs_s1):
        rows = [{"model": row["model"],
                 "średnia różnica FPR (S2 - S1)": f"{row['fpr_mean_difference']:+.3f}",
                 "FPR niższy w sesjach": f"{int(row['fpr_lower_in'])} z {int(row['sessions'])}",
                 "średnia różnica recall (S2 - S1)": f"{row['recall_mean_difference']:+.3f}",
                 "recall wyższy w sesjach": f"{int(row['recall_higher_in'])} z {int(row['sessions'])}"}
                for _, row in s2_vs_s1.sort_values("model", key=lambda c: c.map(order)).iterrows()]
        children += [heading("Czy adaptacja na M0 (S2) pomaga względem transferu bez adaptacji (S1)"),
                     dash_table.DataTable(data=rows, columns=[{"name": c, "id": c} for c in rows[0]],
                                          style_header=table_header, style_cell=table_cell,
                                          style_cell_conditional=centered(list(rows[0])[1:]),
                                          style_header_conditional=centered(list(rows[0])[1:]))]
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
            control("scenariusz", dcc.Dropdown([{"label": SCENARIO_LABELS.get(s, s), "value": s} for s in SCENARIOS],
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
    # takiego biegu nie ma (np. S2 nie liczono dla T_check): zostaje poprzedni, napis mówi dlaczego
    if not os.path.isdir(run_folder(scenario, variant, session)):
        return (no_update, no_update, no_update, no_update,
                f"Brak predykcji {scenario} dla wariantu {variant} i sesji {session} "
                f"(results/raw/{scenario}_{variant}_{session}); odtwarzany jest poprzedni bieg.")
    # global: pozostałe funkcje czytają te zmienne modułu, więc podmiana tutaj działa w całej aplikacji
    global flows, thresholds, attacks, session_start, session_length, models
    flows, thresholds, attacks, session_start, session_length = load_run(scenario, variant, session)
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


# po każdej zmianie czasu baza alarmów jest uzupełniana (do przodu) albo przycinana (do tyłu);
# przy otwarciu strony suwak stoi na 0, więc baza jest czyszczona
@app.callback(Output("clock", "data"), Input("seek", "value"), State("clock", "data"))
def sync_alerts(seek, clock):
    if seek > clock:
        # od zera włącznie, żeby nie zgubić pierwszego przepływu (t = 0)
        save_alerts(clock if clock > 0 else -1, seek)
    else:
        remove_alerts_after(seek if seek > 0 else -1)
    return seek


# Główny callback: po każdej zmianie czasu, modelu albo filtra przelicza wszystko, co widać, na podstawie
# przepływów, które zaczęły się do bieżącej chwili (seen): kafelki, tabelę alarmów, oś czasu,
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
                     "wykryte": result["tp"], "fałszywe alarmy": result["fp"]})
        per_attack = classic_models.recall_per_attack(seen["attack_type"].to_numpy(), seen[f"score_{name}"].to_numpy(),
                                                      thresholds[name])
        recall_figure.add_bar(x=list(per_attack.keys()), y=list(per_attack.values()), name=name,
                              marker_color=MODEL_COLORS.get(name))
    recall_figure.update_layout(title="Recall per atak (odtworzona część sesji)", yaxis_range=[0, 1.05],
                                barmode="group", yaxis_title="recall")
    style_figure(recall_figure)

    metrics = dash_table.DataTable(
        data=rows, columns=[{"name": c, "id": c} for c in ["model", "recall", "FPR", "wykryte", "fałszywe alarmy"]],
        style_header=table_header,
        style_cell=table_cell,
    )
    delays = dash_table.DataTable(
        data=detection_delays(seen), columns=[{"name": c, "id": c} for c in ["atak", "start [s]"] + models],
        style_header=table_header,
        style_cell=table_cell,
    )
    share = seen["label"].mean() if len(seen) else 0
    note = html.Div(f"Udział ataków w odtworzonej części sesji: {share:.0%}. Recall i FPR od niego nie zależą; "
                    f"precision i F1 by zależały, dlatego ich tu nie ma.", className="hint")

    label = f"{int(clock) // 60}:{int(clock) % 60:02d} / {int(session_length) // 60}:{int(session_length) % 60:02d}"
    delay_title = html.Div("Opóźnienie detekcji [s]: od startu ataku do pierwszego trafionego alarmu "
                           "(- = jeszcze nie wykryty)", className="control-label", style={"marginTop": "20px"})
    return cards, table, timeline, [metrics, note, delay_title, delays], recall_figure, label, hosts


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8050, debug=False)
