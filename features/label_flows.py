#!/usr/bin/env python3
"""Etykietowanie przepływów: łączy tabelę cech z ground truth i dodaje etykiety.

Jedna reguła dla wszystkich danych (Mininet, GeNIS, CIC-IDS2017; label_genis.py i label_cic.py
tylko wczytują swoje ground truth i wołają funkcje z tego pliku). Przepływ dostaje etykietę ataku,
jeśli łączy atakującego z celem (w dowolnym kierunku), ma port usługi i protokół ataku (gdy są
podane), a CZAS STARTU przepływu mieści się w oknie [start, end] ataku. W przeciwnym razie przepływ
jest normalny. Na granicy okna decyduje czas startu.

Dwa poziomy etykiet:
  - label        (binarna):  0 = normalny, 1 = atak
  - attack_type  (wieloklasowa): normal, port_scan, ssh_bruteforce, dos_slow, http_flood, c2_beaconing,
                 "poza_zakresem" (atak ze zbioru publicznego, którego nie używamy) albo
                 "attempted": przepływ ataku TCP, w którym atakujący nie wysłał żadnych danych
                 (np. połączenie odrzucone przez przeciążony serwer). Takie przepływy nie niosą treści
                 ataku, więc nie trafiają do treningu ani do testu (Engelen i in. 2021; Liu i in. 2022).
                 Skanu portów to nie dotyczy, bo skan z definicji nie wysyła danych.
                 W Mininecie attempted dostają też końcówki ataków: przepływy TCP bez danych
                 do END_GRACE_S po końcu okna (pakiety zamykające połączenia narzędzia).

    python3 features/label_flows.py --flows <plik_lub_katalog> --ground-truth gt.jsonl --out labeled.parquet
"""
import argparse
import glob
import json
import os
import sys

import pandas as pd

START_MS = "bidirectional_first_seen_ms"
ATTEMPTED = "attempted"
OUT_OF_SCOPE = "poza_zakresem"
PROTOCOL_NUMBER = {"tcp": 6, "udp": 17, "icmp": 1}  # numery protokołów w kolumnie "protocol" z NFStream
# Końcówka ataku w Mininecie: koniec okna to chwila, w której narzędzie oddało sterowanie, a pakiety
# zamykające jego połączenia (pojedyncze RST/FIN, bez danych) docierają na r0 dopiero po opóźnieniu łącza
# (WAN 20 ms) i otwierają nowe przepływy tuż po końcu okna (zmierzone: 0,06 s po końcu A3). Takie
# przepływy TCP bez danych od atakującego, które zaczynają się do END_GRACE_S po końcu okna, dostają
# klasę attempted (poza treningiem i testem). Przepływy z danymi zostają normalne, więc ruch normalny
# atakującego hosta, wznowiony zaraz po ataku, nie dostaje etykiety ataku.
END_GRACE_S = 2.0


# Czas startu każdego przepływu w sekundach (NFStream podaje milisekundy od 1970, ground truth sekundy).
def flow_start_seconds(flows):
    return pd.to_numeric(flows[START_MS], errors="coerce") / 1000.0


# Prawda dla przepływów, które należą do ataku.
#
# attack: attacker_ip, start, end oraz opcjonalnie target_ips (lista; brak = dowolny cel),
# service_port i protocol (brak = dowolny). Oba kierunki się liczą: zwykle przepływ zaczyna
# atakujący, ale gdy połączenie zostanie zerwane (RST), pakiet doslany chwilę później przez serwer
# otwiera nowy przepływ cel -> atakujący. To nadal ten sam atak (decyzja z 26.10.2026).
def flows_matching_attack(flows, attack, start_seconds):
    target_ips = attack.get("target_ips")
    service_port = attack.get("service_port")

    # jeden kierunek reguły: kolumna z adresem atakującego, kolumna z adresem celu i kolumna z portem usługi
    def one_direction(attacker_column, target_column, port_column):
        matches = flows[attacker_column] == attack["attacker_ip"]
        if target_ips:
            matches &= flows[target_column].isin(target_ips)
        if service_port is not None:
            matches &= flows[port_column] == service_port
        return matches

    # atakujący -> cel (port usługi = port docelowy) albo cel -> atakujący (port usługi = port źródłowy)
    matches = one_direction("src_ip", "dst_ip", "dst_port") | one_direction("dst_ip", "src_ip", "src_port")
    if attack.get("protocol") is not None:
        matches &= flows["protocol"] == attack["protocol"]
    return matches & (start_seconds >= attack["start"]) & (start_seconds <= attack["end"])


# Przepływy ataku (mask) bez żadnych danych od atakującego. Przepływ mógł zacząć atakujący
# albo cel (np. resztka po RST), więc dane atakującego są w src2dst albo w dst2src.
def is_attempted(flows, attack_type, attacker_ip, mask):
    if attack_type == "port_scan":
        return mask & False  # skan nigdy nie wysyła danych, więc tu nic nie jest „attempted”
    if "src2dst_payload_bytes" not in flows.columns:
        sys.exit("Brak kolumn *_payload_bytes: przelicz przepływy aktualnym extract_flows.py.")
    # bajty od atakującego: src2dst, gdy przepływ zaczął atakujący, w przeciwnym razie dst2src
    attacker_payload = flows["src2dst_payload_bytes"].where(flows["src_ip"] == attacker_ip,
                                                            flows["dst2src_payload_bytes"])
    return mask & (flows["protocol"] == PROTOCOL_NUMBER["tcp"]) & (attacker_payload == 0)


# Przepływy z końcówki ataku (END_GRACE_S wyżej): ta sama para atakujący-cel, start w (end, end + grace],
# TCP bez danych od atakującego. Dotyczy każdego typu ataku, także skanu.
def tail_flows(flows, attack, start_seconds, grace):
    if grace <= 0:
        return pd.Series(False, index=flows.index)
    tail_window = dict(attack, start=attack["end"], end=attack["end"] + grace)
    mask = flows_matching_attack(flows, tail_window, start_seconds) & (start_seconds > attack["end"])
    return is_attempted(flows, "tail", attack["attacker_ip"], mask)


# Dodaje kolumny label i attack_type. attacks: lista ataków z kluczem type (nasza klasa) i polami
# reguły (flows_matching_attack). Pierwszy pasujący atak wygrywa (kolejność ground truth).
# end_grace_s > 0 (tylko Mininet) dodatkowo oznacza końcówki ataków jako attempted.
def label(flows, attacks, end_grace_s=0.0):
    flows = flows.copy()
    flows["label"] = 0
    flows["attack_type"] = "normal"
    start_seconds = flow_start_seconds(flows)
    for attack in attacks:
        # tylko przepływy jeszcze nieoznaczone - dzięki temu wygrywa pierwszy pasujący atak
        to_label = flows_matching_attack(flows, attack, start_seconds) & (flows["attack_type"] == "normal")
        flows.loc[to_label, "label"] = 1
        flows.loc[to_label, "attack_type"] = attack["type"]
        # attempted zostaje z label = 1, ale osobną klasą; modele usuwają ją z treningu i testu
        if attack["type"] != OUT_OF_SCOPE:
            flows.loc[is_attempted(flows, attack["type"], attack["attacker_ip"], to_label), "attack_type"] = ATTEMPTED
    # końcówki po wszystkich oknach, żeby przepływ z końcówki jednego ataku nie zasłonił okna następnego
    for attack in attacks:
        if attack["type"] == OUT_OF_SCOPE:
            continue
        tail = tail_flows(flows, attack, start_seconds, end_grace_s) & (flows["attack_type"] == "normal")
        flows.loc[tail, "label"] = 1
        flows.loc[tail, "attack_type"] = ATTEMPTED
    return flows


# Zbiory publiczne: etykietuje każde nagranie (plik .parquet z extract_flows.py) i skleja je
# w jedną tabelę z kolumnami source i recording (nazwa nagrania).
def label_recordings(folder, attacks, source):
    labeled_recordings = []
    for path in sorted(glob.glob(os.path.join(folder, "*.parquet"))):
        recording = os.path.basename(path).replace(".parquet", "")
        labeled = label(pd.read_parquet(path), attacks)
        labeled["source"] = source
        labeled["recording"] = recording
        labeled_recordings.append(labeled)
        print(f"  {recording:28s} przepływy: {len(labeled):7d}  klasy: {labeled['attack_type'].value_counts().to_dict()}")
    return pd.concat(labeled_recordings, ignore_index=True)


# Wczytuje plik .parquet albo wszystkie .parquet z katalogu (wynik extract_flows.py).
def load_flows(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "*.parquet"), recursive=True))
    else:
        files = [path]
    tables = [table for table in (pd.read_parquet(file) for file in files) if not table.empty]
    if not tables:
        sys.exit(f"Brak niepustych plików .parquet w {path}")
    return pd.concat(tables, ignore_index=True)


# ground_truth.jsonl z orkiestratora (Mininet): jeden atak na linię, pola type, attacker_ip, target_ips...
def load_ground_truth(path):
    with open(path) as file:
        return [json.loads(line) for line in file if line.strip()]


# Zapis oetykietowanej tabeli do .parquet i krótkie podsumowanie klas na ekranie.
def save(flows, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    flows.to_parquet(path, index=False)
    attacks = int((flows["label"] == 1).sum())
    print(f"Przepływy: {len(flows)}  (atak: {attacks}, {100 * attacks / len(flows):.1f}%)")
    for attack_type, count in flows["attack_type"].value_counts().items():
        print(f"  {attack_type:16s} {count}")
    print(f"Zapisano: {path}")


# Etykietowanie jednej sesji z Mininetu: przepływy + ground_truth.jsonl -> plik z etykietami.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", required=True, help="plik .parquet albo katalog z wynikami extract_flows.py")
    parser.add_argument("--ground-truth", required=True, help="ground_truth.jsonl z orkiestratora")
    parser.add_argument("--out", required=True, help="wyjściowy plik .parquet")
    args = parser.parse_args()
    save(label(load_flows(args.flows), load_ground_truth(args.ground_truth), END_GRACE_S), args.out)


if __name__ == "__main__":
    main()
