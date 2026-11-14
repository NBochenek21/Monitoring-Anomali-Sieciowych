#!/usr/bin/env python3
"""Parsery logów narzędzi ataków: ile prób/żądań/portów/check-inów narzędzie zaraportowało.

Używane przez features/check_labels.py (niezależna kontrola etykiet: porównanie z liczbą
oetykietowanych przepływów). Tylko odczyt plików - bez
zależności od mininetu, więc check_labels można uruchomić bez stawiania sieci.
"""
import os #sprawdzenie czy log istnieje
import re #regexy

#liczy linie z /tcp i open w wyjściu nmap - zwraca liczbę otwartych portów
#używane w check_labels tylko jako informacja (A1)
def nmap_open_ports(log):
    if not os.path.exists(log):
        return 0
    with open(log) as f:
        return sum(1 for line in f if "/tcp" in line and "open" in line)


# Liczba portów, które nmap naprawdę sprawdził, z logu -oN: dla każdego hosta "Not shown: N closed
# ports" (albo "All N scanned ports ... are closed") plus wypisane wiersze portów. Hosty, których
# nmap nie uznał za działające, nie mają raportu, więc nie wchodzą do sumy. None, gdy logu nie ma
# albo nie ma w nim żadnego raportu hosta (wtedy check_labels użyje konfiguracji).
def nmap_scanned_ports(log):
    if not os.path.exists(log):
        return None
    total, reports = 0, 0
    with open(log) as f:
        for line in f:
            if line.startswith("Nmap scan report for"):
                reports += 1
            m = re.match(r"Not shown: (\d+) ", line) or re.match(r"All (\d+) scanned ports", line)
            if m:
                total += int(m.group(1))
            elif re.match(r"\d+/(tcp|udp)\s", line):
                total += 1
    return total if reports else None


# Liczba połączeń, które slowhttptest otworzył, z ostatniego raportu stanu w logu:
# initializing + pending + connected + error + closed. Log zawiera kody kolorów ANSI
# i powrót karetki, które trzeba usunąć. None, gdy logu nie ma albo nie ma w nim raportu.
def slowhttptest_connections(log):
    if not os.path.exists(log):
        return None
    with open(log, errors="replace") as f:
        text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", f.read())
    fields = ("initializing", "pending", "connected", "error", "closed")
    last = {}
    for name, value in re.findall(rf"({'|'.join(fields)}):\s+(\d+)", text):
        last[name] = int(value)
    return sum(last.values()) if last else None

#regex - liczby próby a kod =='0' to trafienia, zwraca krotkę (próby, trafienia)
#to stąd check_labels bierze liczbe dla A2
# Log patatora: każda próba to linia 'INFO - <code> <size> <time> | <hasło> | ...'.
# hits = próby z kodem 0 (udane uwierzytelnienie).
def patator_attempts(log):
    if not os.path.exists(log):
        return 0, 0
    pat = re.compile(r"INFO - (\d+)\s+\d+\s+[\d.]+ \|")
    attempts = hits = 0
    with open(log) as f:
        for line in f:
            m = pat.search(line)
            if m:
                attempts += 1
                if m.group(1) == "0":
                    hits += 1
    return attempts, hits

#regex - z całego pliku
def flood_requests(log):
    if not os.path.exists(log):
        return 0
    with open(log) as f:
        m = re.search(r"requests=(\d+)", f.read())
    return int(m.group(1)) if m else 0

#liczy linie z checkin i exfil w logu klienta (attacks/tools/beacon_client.py, tool_log z ground truth),
#linie error pomija
def beacon_count(log):
    if not os.path.exists(log):
        return 0
    with open(log) as f:
        return sum(1 for line in f if "\tcheckin" in line or "\texfil" in line)
