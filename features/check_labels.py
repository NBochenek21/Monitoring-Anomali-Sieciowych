#!/usr/bin/env python3
"""Kontrola spójności etykiet: porównuje oetykietowaną tabelę z ground truth.

Sprawdza cztery rzeczy:
  1. każdy przepływ z etykietą ataku spełnia regułę (źródło, cel, czas startu w oknie),
  2. żaden przepływ z etykietą normal jej nie spełnia (brak pominiętych ataków),
  3. NIEZALEŻNIE (w przybliżeniu, np. kilka żądań HTTP może iść jednym połączeniem):
     liczba oetykietowanych przepływów danego ataku zgadza się z logiem samego
     narzędzia (patator: próby, nmap: przeskanowane porty z raportów hostów, flood: żądania,
     beacon: check-iny, slowhttptest: połączenia z ostatniego raportu stanu). Gdy log nie ma
     raportu, nmap i slowhttptest wracają do konfiguracji i opis to zaznacza. Punkty 1-2 sprawdzają
     regułę samą ze sobą; punkt 3 konfrontuje etykiety z niezależnym źródłem - tym, co narzędzie
     naprawdę zrobiło,
  4. żaden przepływ TCP z etykietą ataku nie jest dalszym ciągiem starszego połączenia (bez SYN,
     z danymi), np. połączenia workera wstrzymanego na czas ataku.

    python3 features/check_labels.py --labeled labeled.parquet --ground-truth gt.jsonl
"""
import argparse
import os
import sys

import pandas as pd

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "attacks"))
import tool_logs  # noqa: E402

from label_flows import (END_GRACE_S, flow_start_seconds, flows_matching_attack,  # noqa: E402
                         load_ground_truth, tail_flows)


# Liczba portów w specyfikacji nmap, np. '1-1024' albo '22,80,443'.
def ports_in_range(ports_spec):
    total = 0
    for part in str(ports_spec).split(","):
        part = part.strip()
        if "-" in part:
            low, high = part.split("-")
            total += int(high) - int(low) + 1
        elif part:
            total += 1
    return total


# Niezależny szacunek liczby przepływów ataku z logu narzędzia (konfiguracja tylko awaryjnie).
# Zwraca (opis, oczekiwana_liczba); oczekiwana_liczba = None, gdy nie da się oszacować.
def expected_flows(attack):
    attack_type = attack["type"]
    log = attack.get("tool_log", "")
    params = attack.get("params", {})
    if attack_type == "ssh_bruteforce":
        attempts, hits = tool_logs.patator_attempts(log)
        return f"patator: {attempts} prob ({hits} udanych)", attempts
    if attack_type == "c2_beaconing":
        bc = tool_logs.beacon_count(log)
        return f"beacon: {bc} check-inow/exfil", bc
    if attack_type == "http_flood":
        req = tool_logs.flood_requests(log)
        return f"flood: {req} zadan", req
    if attack_type == "dos_slow":
        conn = tool_logs.slowhttptest_connections(log)
        if conn is not None:
            return f"slowhttptest (log): {conn} polaczen", conn
        conn = params.get("connections")
        return f"slowhttptest (konfiguracja, brak raportu w logu): {conn} polaczen", conn
    if attack_type == "port_scan":
        open_ports = tool_logs.nmap_open_ports(log)
        probes = tool_logs.nmap_scanned_ports(log)
        if probes is not None:
            return f"nmap (log): {probes} portow ({open_ports} open)", probes
        probes = ports_in_range(params.get("ports", "")) * max(1, len(attack.get("target_ips", [])))
        return f"nmap (konfiguracja, brak raportu w logu): ~{probes} prob ({open_ports} open)", probes
    return "brak", None


# Obie kontrole dla jednej sesji; kod wyjścia 0 = OK, 1 = błąd (record_all.sh zapisuje wynik do logu).
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--labeled", required=True)
    parser.add_argument("--ground-truth", required=True)
    args = parser.parse_args()

    flows = pd.read_parquet(args.labeled)
    attacks = load_ground_truth(args.ground_truth)
    start_seconds = flow_start_seconds(flows)

    # kontrola 1 i 2: zaznaczam przepływy, które spełniają regułę któregokolwiek ataku,
    # i porównuję z etykietami zapisanymi w pliku
    any_rule = pd.Series(False, index=flows.index)
    any_tail = pd.Series(False, index=flows.index)
    per_attack = []
    for attack in attacks:
        matches = flows_matching_attack(flows, attack, start_seconds)
        any_rule |= matches
        any_tail |= tail_flows(flows, attack, start_seconds, END_GRACE_S)
        per_attack.append((attack, int(matches.sum())))

    # końcówki ataków (label_flows.END_GRACE_S) mają label = 1 i klasę attempted, choć leżą tuż za oknem
    tail_ok = any_tail & (flows["attack_type"] == "attempted")
    wrong_attack = int(((flows["label"] == 1) & ~any_rule & ~tail_ok).sum())
    missed = int(((flows["label"] == 0) & (any_rule | any_tail)).sum())

    print(f"Przepływy z etykietą ataku niespełniające reguły: {wrong_attack}")
    print(f"Przepływy 'normal' spełniające regułę ataku (pominięte): {missed}")
    print(f"Końcówki ataków (do {END_GRACE_S:g} s po oknie, bez danych) jako attempted: {int(tail_ok.sum())}")
    # kontrola 4: przepływ TCP z etykietą ataku bez SYN, a z danymi, to dalszy ciąg połączenia otwartego
    # przed oknem - np. połączenia workera wstrzymanego SIGSTOP na czas ataku, które NFStream po 60 s
    # bezczynności otwiera jako nowy przepływ w oknie. Połączenia narzędzi ataku zaczynają się od SYN,
    # a resztki po RST nie niosą danych (te są attempted).
    continued = int(((flows["label"] == 1) & (flows["attack_type"] != "attempted") & (flows["protocol"] == 6)
                     & (flows["bidirectional_syn_packets"] == 0)
                     & (flows["src2dst_payload_bytes"] + flows["dst2src_payload_bytes"] > 0)).sum())
    print(f"Przepływy ataku TCP bez SYN, z danymi (dalszy ciąg starszego połączenia): {continued}")
    print("Przepływy na atak z ground truth:")
    for attack, count in per_attack:
        print(f"  {attack['attack_id']:20s} {attack['type']:16s} {count}")

    print("Niezależna kontrola (oetykietowane przepływy vs log narzędzia):")
    tool_problem = False
    for attack, count in per_attack:
        desc, expected = expected_flows(attack)
        if not expected:  # None albo 0 -> nie da się oszacować (np. brak logu narzędzia)
            print(f"  ----   {attack['attack_id']:20s} przepływów={count:<5d} {desc} (brak szacunku)")
            continue
        # kontrola 3: stosunek przepływów do liczby z logu narzędzia; ok. 1 = zgodnie.
        # 0,5-2 to OK (np. kilka żądań HTTP w jednym połączeniu), poza 0,3-3 albo 0 przepływów to błąd
        ratio = count / expected
        gross = count == 0 or ratio < 0.3 or ratio > 3.0
        flag = "BŁĄD " if gross else ("OK   " if 0.5 <= ratio <= 2.0 else "UWAGA")
        tool_problem = tool_problem or gross
        print(f"  {flag}  {attack['attack_id']:20s} przepływów={count:<5d} oczek.~{expected:<6d} "
              f"x{ratio:.2f}  ({desc})")

    ok = wrong_attack == 0 and missed == 0 and continued == 0 and not tool_problem
    print("WYNIK:", "OK" if ok else "BŁĄD")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
