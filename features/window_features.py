#!/usr/bin/env python3
"""Cechy kontekstu hosta: co host robił w ostatnich 60 s przed końcem przepływu.

Dla każdego przepływu: liczba przepływów, celów i portów hosta oraz udział RST w ostatnich 60 s,
a także regularność połączeń do tego samego celu (CV odstępów 5 ostatnich przepływów; blisko 0 =
bardzo regularnie jak beacon albo IoT, 1 = za mało przepływów). Czas przepływu to jego koniec (ostatni
pakiet) i liczę tylko wstecz, więc nie ma zaglądania w przyszłe pakiety. Przepływ zamknięty przez
TCP (FIN, RST) sonda oddaje od razu, a zamknięty po 60 s bezczynności dopiero ok. 60 s po ostatnim
pakiecie (w M1 prawie tylko UDP, ok. 3% przepływów), więc dla takich przepływów chwila decyzji jest późniejsza.
Tu jest też window_rows: okno 8 ostatnich przepływów hosta dla FlowTransformera.
"""
import numpy as np

WINDOW_SECONDS = 60
PAIR_FLOWS = 5  #ile ostatnich przepływów do tego samego celu bierze regularność (4 odstępy)

WINDOW_FEATURES = ["host_flows_60s", "host_destinations_60s", "host_ports_60s",
                   "host_rst_share_60s", "host_dst_gap_cv"]
START = "bidirectional_first_seen_ms"
END = "bidirectional_last_seen_ms"


#Kolumna czasu, po której porządkuję przepływy: koniec, a gdy go nie ma - start.
def time_column(flows):
    return END if END in flows.columns else START


#licznik wartości w oknie (słownik wartość -> ile razy): dodanie jednego wystąpienia.
#liczba kluczy słownika = liczba różnych celów albo portów w oknie.
def add_to_counter(counter, value):
    counter[value] = counter.get(value, 0) + 1


#usunięcie jednego wystąpienia; gdy licznik spadnie do 0, wartość znika z okna.
def remove_from_counter(counter, value):
    counter[value] -= 1
    if counter[value] == 0:
        del counter[value]


#zmienność odstępów 5 ostatnich przepływów do tego samego celu (host_dst_gap_cv).
def pair_regularity(flows, group_columns):
    keys = group_columns + ["dst_ip"]
    when = time_column(flows)
    ordered = flows.sort_values(keys + [when, START], kind="stable")
    #odstęp przed przepływem; pierwszy przepływ pary nie ma odstępu (NaN), więc okno 4 odstępów,
    #które zahacza o poprzednią parę, też daje NaN i nie miesza par
    gaps = ordered.groupby(keys, sort=False)[when].diff() / 1000
    window = gaps.rolling(PAIR_FLOWS - 1)
    mean = window.mean()
    #CV = odchylenie / średnia; mean.where(mean > 0) zamienia średnią 0 na NaN, żeby nie dzielić przez 0
    cv = window.std(ddof=0) / mean.where(mean > 0)
    cv[mean == 0] = 0.0  #wszystkie przepływy w tej samej milisekundzie = idealnie regularnie
    #naN (za mało przepływów do tego celu) -> 1, czyli "jak losowy ruch"; reindex wraca do kolejności wejścia
    return cv.fillna(1.0).reindex(flows.index).to_numpy()


#zwraca kopię tabeli przepływów z pięcioma kolumnami cech kontekstu hosta.
def add_window_features(flows, window_seconds=WINDOW_SECONDS):
    flows = flows.reset_index(drop=True).copy()
    values = {name: np.zeros(len(flows)) for name in WINDOW_FEATURES[:4]}

    group_columns = ["src_ip"]
    if "recording" in flows.columns:
        group_columns = ["recording", "src_ip"]

    #każdy host osobno, przepływy po kolei według końca; okno przesuwa się do przodu (left = najstarszy
    #przepływ w ostatnich 60 s), a liczniki zmieniam tylko o to, co weszło i wyszło z okna - szybko
    when = time_column(flows)
    for _, host_flows in flows.groupby(group_columns, sort=False):
        host_flows = host_flows.sort_values([when, START], kind="stable")
        rows = host_flows.index.to_numpy()
        times = host_flows[when].to_numpy() / 1000
        destinations = host_flows["dst_ip"].to_numpy()
        ports = host_flows["dst_port"].to_numpy()
        rst_sum = np.cumsum(host_flows["bidirectional_rst_packets"].to_numpy() > 0)  #suma narastająca

        destination_counter = {}
        port_counter = {}
        left = 0
        for current in range(len(rows)):
            add_to_counter(destination_counter, destinations[current])
            add_to_counter(port_counter, ports[current])
            #usuwam z okna przepływy starsze niż 60 s
            while times[current] - times[left] > window_seconds:
                remove_from_counter(destination_counter, destinations[left])
                remove_from_counter(port_counter, ports[left])
                left += 1

            flows_in_window = current - left + 1
            #liczba przepływów z RST w oknie z sumy narastającej: suma do bieżącego minus suma przed oknem
            rst_in_window = rst_sum[current] - (rst_sum[left - 1] if left > 0 else 0)
            row = rows[current]
            values["host_flows_60s"][row] = flows_in_window
            values["host_destinations_60s"][row] = len(destination_counter)
            values["host_ports_60s"][row] = len(port_counter)
            values["host_rst_share_60s"][row] = rst_in_window / flows_in_window

    for name in WINDOW_FEATURES[:4]:
        flows[name] = values[name]
    flows["host_dst_gap_cv"] = pair_regularity(flows, group_columns)
    return flows


#okno FlowTransformera: dla każdego przepływu z rows numery wierszy 8 ostatnich zakończonych przepływów
#tego samego hosta (on sam na końcu); -1 = brak przepływu (w oknie będą zera)
#historia z całej tabeli flows (także attempted), okna tylko dla rows; wynik ma kształt (len(rows), size)
def window_rows(flows, rows, size):
    host_keys = flows["src_ip"].astype(str).to_numpy()
    if "recording" in flows.columns:  #zbiory publiczne: ten sam adres w różnych nagraniach to różne hosty
        host_keys = flows["recording"].astype(str).to_numpy() + "/" + host_keys
    #kolejność: host, a w nim czas końca (przy równym końcu start); positions[k] = wiersz, który
    #w tej kolejności jest k-ty. lexsort sortuje po ostatnim kluczu najpierw.
    positions = np.lexsort((flows[START].to_numpy(), flows[time_column(flows)].to_numpy(), host_keys))
    rank = np.empty(len(flows), dtype="int64")
    rank[positions] = np.arange(len(flows))
    sorted_hosts = host_keys[positions]
    #pierwsza pozycja bloku każdego hosta (dla każdej pozycji w kolejności)
    new_host = np.r_[True, sorted_hosts[1:] != sorted_hosts[:-1]]
    host_start = np.maximum.accumulate(np.where(new_host, np.arange(len(flows)), 0))
    current = rank[np.asarray(rows)]
    window = current[:, None] + np.arange(-size + 1, 1)  #pozycje size ostatnich przepływów
    inside = window >= host_start[current][:, None]       #tylko przepływy tego samego hosta
    return np.where(inside, positions[np.clip(window, 0, None)], -1)
