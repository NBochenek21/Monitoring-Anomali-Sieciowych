#!/usr/bin/env python3
"""Etykiety przepływów: jedna reguła dla Mininetu, CIC-IDS2017 i GeNIS.

Przepływ jest atakiem, gdy łączy atakującego z celem (w dowolnym kierunku), ma port i protokół usługi
(jeśli podane) i zaczyna się w oknie ataku z ground truth. Dodaje kolumny label (0/1) i attack_type.
attempted = przepływ ataku TCP bez danych od atakującego (np. odrzucony przez serwer) i końcówki ataku
do 2 s po oknie (końcówka tylko w Mininecie; CIC i GeNIS mają okna z ground truth zbioru); nie trafia
do treningu ani testu. poza_zakresem = atak, którego nie używam.

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
PROTOCOL_NUMBER = {"tcp": 6, "udp": 17, "icmp": 1}  #numery protokołów w kolumnie "protocol" z NFStream
#końcówka ataku w Mininecie: pakiety zamykające połączenia narzędzia (RST/FIN bez danych) dochodzą
#na r0 chwilę po końcu okna i tworzą nowe przepływy; przepływy TCP bez danych od atakującego do 2 s
#po oknie dostają klasę attempted (poza treningiem i testem); przepływy z danymi zostają normalne,
#więc ruch atakującego hosta wznowiony po ataku nie dostaje etykiety ataku
END_GRACE_S = 2.0


#Czas startu każdego przepływu w sekundach (NFStream podaje milisekundy od 1970, ground truth sekundy).
def flow_start_seconds(flows):
    return pd.to_numeric(flows[START_MS], errors="coerce") / 1000.0


#które przepływy należą do ataku: atakujący <-> cel, port i protokół usługi (jeśli podane),
#start przepływu w oknie [start, end] ataku
#oba kierunki, bo po zerwanym połączeniu (RST) pakiet serwera może otworzyć przepływ cel -> atakujący
def flows_matching_attack(flows, attack, start_seconds):
    target_ips = attack.get("target_ips")
    service_port = attack.get("service_port")

    #jeden kierunek reguły: kolumna z adresem atakującego, kolumna z adresem celu i kolumna z portem usługi
    def one_direction(attacker_column, target_column, port_column):
        matches = flows[attacker_column] == attack["attacker_ip"]
        if target_ips:
            matches &= flows[target_column].isin(target_ips)
        if service_port is not None:
            matches &= flows[port_column] == service_port
        return matches

    #atakujący -> cel (port usługi = port docelowy) albo cel -> atakujący (port usługi = port źródłowy)
    matches = one_direction("src_ip", "dst_ip", "dst_port") | one_direction("dst_ip", "src_ip", "src_port")
    if attack.get("protocol") is not None:
        matches &= flows["protocol"] == attack["protocol"]
    return matches & (start_seconds >= attack["start"]) & (start_seconds <= attack["end"])


#przepływy ataku, w których atakujący nie wysłał żadnych danych (klasa attempted)
#dane atakującego są w src2dst albo dst2src - zależy, kto zaczął przepływ
def is_attempted(flows, attack_type, attacker_ip, mask):
    if attack_type == "port_scan":
        return mask & False  #skan nigdy nie wysyła danych, więc tu nic nie jest "attempted"
    if "src2dst_payload_bytes" not in flows.columns:
        sys.exit("Brak kolumn *_payload_bytes: przelicz przepływy aktualnym extract_flows.py.")
    #bajty od atakującego: src2dst, gdy przepływ zaczął atakujący, w przeciwnym razie dst2src
    attacker_payload = flows["src2dst_payload_bytes"].where(flows["src_ip"] == attacker_ip,
                                                            flows["dst2src_payload_bytes"])
    return mask & (flows["protocol"] == PROTOCOL_NUMBER["tcp"]) & (attacker_payload == 0)


#przepływy z końcówki ataku: ta sama para atakujący-cel, start do 2 s po oknie, TCP bez danych od atakującego
def tail_flows(flows, attack, start_seconds, grace):
    if grace <= 0:
        return pd.Series(False, index=flows.index)
    tail_window = dict(attack, start=attack["end"], end=attack["end"] + grace)
    mask = flows_matching_attack(flows, tail_window, start_seconds) & (start_seconds > attack["end"])
    return is_attempted(flows, "tail", attack["attacker_ip"], mask)


#dodaje kolumny label (0/1) i attack_type; gdy pasuje kilka ataków, wygrywa pierwszy z ground truth
#end_grace_s > 0 (tylko Mininet) oznacza też końcówki ataków jako attempted
def label(flows, attacks, end_grace_s=0.0):
    flows = flows.copy()
    flows["label"] = 0
    flows["attack_type"] = "normal"
    start_seconds = flow_start_seconds(flows)
    for attack in attacks:
        #tylko przepływy jeszcze nieoznaczone - dzięki temu wygrywa pierwszy pasujący atak
        to_label = flows_matching_attack(flows, attack, start_seconds) & (flows["attack_type"] == "normal")
        flows.loc[to_label, "label"] = 1
        flows.loc[to_label, "attack_type"] = attack["type"]
        #attempted zostaje z label = 1, ale osobną klasą; modele usuwają ją z treningu i testu
        if attack["type"] != OUT_OF_SCOPE:
            flows.loc[is_attempted(flows, attack["type"], attack["attacker_ip"], to_label), "attack_type"] = ATTEMPTED
    #końcówki po wszystkich oknach, żeby przepływ z końcówki jednego ataku nie zasłonił okna następnego
    for attack in attacks:
        if attack["type"] == OUT_OF_SCOPE:
            continue
        tail = tail_flows(flows, attack, start_seconds, end_grace_s) & (flows["attack_type"] == "normal")
        flows.loc[tail, "label"] = 1
        flows.loc[tail, "attack_type"] = ATTEMPTED
    return flows


#zbiory publiczne: etykietuje każde nagranie osobno i skleja w jedną tabelę (kolumny source i recording)
def label_recordings(folder, attacks, source):
    paths = sorted(glob.glob(os.path.join(folder, "*.parquet")))
    if not paths:
        raise SystemExit(f"Brak plików .parquet w {folder} (najpierw extract_flows.py).")
    labeled_recordings = []
    for path in paths:
        recording = os.path.basename(path).replace(".parquet", "")
        labeled = label(pd.read_parquet(path), attacks)
        labeled["source"] = source
        labeled["recording"] = recording
        labeled_recordings.append(labeled)
        classes = labeled["attack_type"].value_counts().to_dict()
        print(f"  {recording:28s} przepływy: {len(labeled):7d}  klasy: {classes}")
    return pd.concat(labeled_recordings, ignore_index=True)


#wczytuje plik .parquet albo wszystkie .parquet z katalogu (wynik extract_flows.py).
def load_flows(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "*.parquet"), recursive=True))
    else:
        files = [path]
    tables = [table for table in (pd.read_parquet(file) for file in files) if not table.empty]
    if not tables:
        sys.exit(f"Brak niepustych plików .parquet w {path}")
    return pd.concat(tables, ignore_index=True)


#ground_truth.jsonl z orkiestratora (Mininet): jeden atak na linię, pola type, attacker_ip, target_ips...
def load_ground_truth(path):
    with open(path) as file:
        return [json.loads(line) for line in file if line.strip()]


#zapis oetykietowanej tabeli do .parquet i krótkie podsumowanie klas na ekranie.
def save(flows, path):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    flows.to_parquet(path, index=False)
    attacks = int((flows["label"] == 1).sum())
    print(f"Przepływy: {len(flows)}  (atak: {attacks}, {100 * attacks / len(flows):.1f}%)")
    for attack_type, count in flows["attack_type"].value_counts().items():
        print(f"  {attack_type:16s} {count}")
    print(f"Zapisano: {path}")


#etykietowanie jednej sesji z Mininetu: przepływy + ground_truth.jsonl -> plik z etykietami.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", required=True, help="plik .parquet albo katalog z wynikami extract_flows.py")
    parser.add_argument("--ground-truth", required=True, help="ground_truth.jsonl z orkiestratora")
    parser.add_argument("--out", required=True, help="wyjściowy plik .parquet")
    args = parser.parse_args()
    save(label(load_flows(args.flows), load_ground_truth(args.ground_truth), END_GRACE_S), args.out)


if __name__ == "__main__":
    main()
