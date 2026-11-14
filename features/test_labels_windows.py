#!/usr/bin/env python3
"""Test reguły etykiet (label_flows.py) i okien hosta (window_features.py) na małych tabelach o znanym wyniku.

Sprawdza:
  1. regułę etykiet: oba kierunki przepływu, okno czasu z dokładnymi granicami (start, end, end + 2 s),
     cel, klasa attempted (TCP bez danych od atakującego), skan bez attempted, końcówki ataku
     (END_GRACE_S) i zasadę „pierwszy atak wygrywa”,
  2. regularność połączeń (host_dst_gap_cv): 5 równych odstępów do tego samego celu = 0, za mało
     przepływów = 1, przepływy do innego celu się nie mieszają,
  3. okno FlowTransformera (window_rows): tylko przepływy tego samego hosta, w kolejności czasu,
     z historią także z wierszy, dla których okien nie liczymy; brak historii = -1,
  4. brak look-ahead: z kolumną końca przepływu okno i kontekst biorą tylko przepływy już zakończone.

    python3 features/test_labels_windows.py
"""
import numpy as np
import pandas as pd

from label_flows import END_GRACE_S, label
from window_features import add_window_features, window_rows

ATTACKER, TARGET, OTHER = "10.0.1.12", "10.0.10.12", "10.0.10.10"
results = []


# Zapisuje wynik jednego sprawdzenia i wypisuje go.
def check(name, passed):
    results.append(passed)
    print(f"{'OK  ' if passed else 'BŁĄD'} {name}")


# Tabela przepływów z kolumnami potrzebnymi regule; start w sekundach.
def flows_table(rows):
    columns = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "start", "src2dst_payload_bytes",
               "dst2src_payload_bytes"]
    flows = pd.DataFrame(rows, columns=columns)
    flows["bidirectional_first_seen_ms"] = (flows.pop("start") * 1000).astype("int64")
    return flows


def test_label_rule():
    ssh = {"type": "ssh_bruteforce", "attacker_ip": ATTACKER, "target_ips": [TARGET], "service_port": 22,
           "protocol": 6, "start": 100.0, "end": 200.0}
    flows = flows_table([
        (ATTACKER, TARGET, 40000, 22, 6, 150.0, 50, 30),    # 0: atakujący -> cel, w oknie
        # 1: cel -> atakujący (resztka po RST), dane atakującego w dst2src
        (TARGET, ATTACKER, 22, 40001, 6, 150.0, 0, 10),
        (ATTACKER, TARGET, 40002, 22, 6, 250.0, 50, 30),    # 2: po oknie (i po końcówce)
        (ATTACKER, TARGET, 40003, 22, 6, 160.0, 0, 0),      # 3: w oknie, bez danych od atakującego
        (ATTACKER, TARGET, 40004, 22, 6, 201.0, 0, 0),      # 4: końcówka: 1 s po oknie, bez danych
        (ATTACKER, TARGET, 40005, 22, 6, 201.0, 30, 0),     # 5: 1 s po oknie, z danymi (ruch normalny)
        (ATTACKER, OTHER, 40006, 80, 6, 150.0, 50, 30),     # 6: inny cel
    ])
    labeled = label(flows, [ssh], END_GRACE_S)
    types = list(labeled["attack_type"])
    check("atak w oknie (atakujący -> cel)", types[0] == "ssh_bruteforce")
    check("odwrotny kierunek (cel -> atakujący) to ten sam atak", types[1] == "ssh_bruteforce")
    check("przepływ po oknie jest normalny", types[2] == "normal")
    check("TCP bez danych od atakującego to attempted", types[3] == "attempted" and labeled["label"][3] == 1)
    check("końcówka bez danych do END_GRACE_S po oknie to attempted", types[4] == "attempted")
    check("przepływ z danymi tuż po oknie zostaje normalny", types[5] == "normal")
    check("przepływ do innego celu jest normalny", types[6] == "normal")

    # dokładne granice okna [100, 200] (obustronnie domknięte) i końcówki (200, 202]
    flows = flows_table([
        (ATTACKER, TARGET, 41000, 22, 6, 100.0, 50, 30),    # 0: dokładnie start okna
        (ATTACKER, TARGET, 41001, 22, 6, 200.0, 50, 30),    # 1: dokładnie koniec okna
        (ATTACKER, TARGET, 41002, 22, 6, 99.999, 50, 30),   # 2: 1 ms przed oknem
        (ATTACKER, TARGET, 41003, 22, 6, 202.0, 0, 0),      # 3: dokładnie koniec końcówki, bez danych
        (ATTACKER, TARGET, 41004, 22, 6, 202.001, 0, 0),    # 4: 1 ms po końcówce, bez danych
    ])
    types = list(label(flows, [ssh], END_GRACE_S)["attack_type"])
    check("granice okna: t = start i t = end należą do ataku", types[0] == types[1] == "ssh_bruteforce")
    check("granice okna: 1 ms przed startem jest normalny", types[2] == "normal")
    check("końcówka: t = end + 2,0 s to attempted, 1 ms później normalny",
          types[3] == "attempted" and types[4] == "normal")

    scan = {"type": "port_scan", "attacker_ip": ATTACKER, "target_ips": [TARGET], "start": 100.0, "end": 200.0}
    flows = flows_table([(ATTACKER, TARGET, 50000, 443, 6, 120.0, 0, 0)])
    check("skan bez danych zostaje port_scan (nie attempted)", label(flows, [scan])["attack_type"][0] == "port_scan")

    flood = {"type": "http_flood", "attacker_ip": ATTACKER, "target_ips": [TARGET], "start": 100.0, "end": 200.0}
    flows = flows_table([(ATTACKER, TARGET, 50001, 80, 6, 120.0, 100, 500)])
    check("przepływ w dwóch oknach dostaje klasę pierwszego ataku",
          label(flows, [scan, flood])["attack_type"][0] == "port_scan")


def test_pair_regularity():
    rows = []
    for i in range(6):  # host A -> X co 10 s (regularnie)
        rows.append(("A", "X", 80, 1000 * (10 * i)))
    for t in (3, 17, 41, 44, 70):  # host A -> Y nieregularnie, przeplecione z X
        rows.append(("A", "Y", 80, 1000 * t))
    flows = pd.DataFrame(rows, columns=["src_ip", "dst_ip", "dst_port", "bidirectional_first_seen_ms"])
    flows["bidirectional_rst_packets"] = 0
    result = add_window_features(flows)
    to_x = result[result["dst_ip"] == "X"].sort_values("bidirectional_first_seen_ms")["host_dst_gap_cv"].tolist()
    to_y = result[result["dst_ip"] == "Y"].sort_values("bidirectional_first_seen_ms")["host_dst_gap_cv"].tolist()
    check("pierwsze 4 przepływy do celu: za mało, CV = 1", to_x[:4] == [1.0] * 4)
    check("5 równych odstępów do tego samego celu: CV = 0", to_x[4] == 0.0 and to_x[5] == 0.0)
    check("przepływy do innego celu nie mieszają się z regularnymi", to_y[4] > 0.3)
    first_y = result[(result["dst_ip"] == "Y") & (result["bidirectional_first_seen_ms"] == 3000)]
    check("host_flows_60s liczy przepływy hosta w ostatnich 60 s", int(first_y["host_flows_60s"].iloc[0]) == 2)


def test_window_rows():
    # dwa hosty na przemian; wiersze celowo nie w kolejności czasu
    flows = pd.DataFrame({
        "src_ip": ["A", "B", "A", "B", "A", "A"],
        "bidirectional_first_seen_ms": [30, 10, 10, 20, 20, 40],
        "label": [0, 0, 0, 1, 0, 1],
    })
    history = window_rows(flows, [5, 3], 3)  # okna 3 przepływów dla wiersza 5 (A, t=40) i 3 (B, t=20)
    check("okno: ostatnie przepływy tego samego hosta w kolejności czasu", list(history[0]) == [4, 0, 5])
    check("okno: brak historii = -1, bez przepływów innego hosta", list(history[1]) == [-1, 1, 3])
    check("okno sięga po wiersze, dla których okien nie liczymy", 0 in history[0] and 4 in history[0])
    recorded = flows.assign(recording=["d1", "d1", "d2", "d1", "d2", "d1"])
    check("okno nie łączy nagrań (ten sam adres w innym dniu to inny host)",
          list(window_rows(recorded, [5], 3)[0]) == [-1, 0, 5])

    # bez look-ahead: długi przepływ 0 (start 10, koniec 100) zaczął się przed krótkim 1 (start 20,
    # koniec 30), ale skończył po nim, więc w chwili decyzji o 1 nie jest jeszcze znany
    timed = pd.DataFrame({
        "src_ip": ["A", "A", "A"], "dst_ip": ["X", "X", "Y"], "dst_port": [80, 80, 22],
        "bidirectional_first_seen_ms": [10_000, 20_000, 40_000],
        "bidirectional_last_seen_ms": [100_000, 30_000, 41_000],
        "bidirectional_rst_packets": [1, 0, 0], "label": [0, 0, 0],
    })
    history = window_rows(timed, [1, 2, 0], 3)
    check("okno bez look-ahead: przepływ kończący się później nie trafia do okna wcześniejszego",
          list(history[0]) == [-1, -1, 1] and list(history[1]) == [-1, 1, 2] and list(history[2]) == [1, 2, 0])
    context = add_window_features(timed)
    check("kontekst bez look-ahead: RST długiego przepływu nie liczy się dla krótszego",
          context["host_rst_share_60s"][1] == 0.0 and context["host_flows_60s"][1] == 1)


if __name__ == "__main__":
    test_label_rule()
    test_pair_regularity()
    test_window_rows()
    ok = all(results)
    print("WYNIK:", "OK" if ok else "BŁĄD")
    raise SystemExit(0 if ok else 1)
