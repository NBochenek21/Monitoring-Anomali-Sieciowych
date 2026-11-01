#!/usr/bin/env python3
"""Parsery logów narzędzi ataków: ile prób/żądań/portów/check-inów narzędzie zaraportowało.

Używane przez features/check_labels.py (niezależna kontrola etykiet: porównanie z liczbą
oetykietowanych przepływów). Tylko odczyt plików - bez
zależności od mininetu, więc check_labels można uruchomić bez stawiania sieci.
"""
import os #sprawdzenie czy log istnieje
import re #regexy

#liczy linie z /tcp i open w wyjsciu nmap - zwraca liczbe otwartych portów
#używane w check_labels tylko jako informacja (A1)
def nmap_open_ports(log):
    if not os.path.exists(log):
        return 0
    with open(log) as f:
        return sum(1 for line in f if "/tcp" in line and "open" in line)

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

#liczy linie z checkin i exfil w logu beacon_endpoint , error pomija
def beacon_count(log):
    if not os.path.exists(log):
        return 0
    with open(log) as f:
        return sum(1 for line in f if "\tcheckin" in line or "\texfil" in line)
