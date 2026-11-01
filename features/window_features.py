#!/usr/bin/env python3
"""Cechy kontekstu hosta: co host źródłowy robił przed danym przepływem.

Dla każdego przepływu liczę, patrząc tylko wstecz (od startu przepływu 60 s do tyłu, razem z nim):
  host_flows_60s         - liczba przepływów tego hosta,
  host_destinations_60s  - liczba różnych adresów docelowych,
  host_ports_60s         - liczba różnych portów docelowych,
  host_rst_share_60s     - odsetek przepływów z flagą RST,
oraz regularność połączeń do tego samego celu:
  host_dst_gap_cv        - zmienność odstępów między startami 5 ostatnich przepływów tego hosta do tego
                           samego adresu docelowego: odchylenie / średnia (blisko 0 = bardzo regularnie,
                           jak beacon C2 albo heartbeat IoT; 1 = za mało przepływów, by to ocenić).
                           Bez limitu 60 s, bo beacon co ok. 45 s ma w 60 s najwyżej 2 przepływy.
                           Okresowość C2 bada się właśnie dla pary klient-serwer (Bilge i in. 2012).

Wszystko liczę osobno w każdym nagraniu (kolumna recording w zbiorach publicznych), żeby nie łączyć
przepływów z różnych dni. Patrzę tylko wstecz, więc cechy są dostępne w chwili startu przepływu.
Cechy trzeba liczyć na pełnych danych, zanim wybierze się próbkę do treningu.
"""
import numpy as np

WINDOW_SECONDS = 60
PAIR_FLOWS = 5  # ile ostatnich przepływów do tego samego celu bierze regularność (4 odstępy)

WINDOW_FEATURES = ["host_flows_60s", "host_destinations_60s", "host_ports_60s",
                   "host_rst_share_60s", "host_dst_gap_cv"]
START = "bidirectional_first_seen_ms"


# Licznik wartości w oknie (słownik wartość -> ile razy): dodanie jednego wystąpienia.
# Liczba kluczy słownika = liczba różnych celów albo portów w oknie.
def add_to_counter(counter, value):
    counter[value] = counter.get(value, 0) + 1


# Usunięcie jednego wystąpienia; gdy licznik spadnie do 0, wartość znika z okna.
def remove_from_counter(counter, value):
    counter[value] -= 1
    if counter[value] == 0:
        del counter[value]


# Zmienność odstępów 5 ostatnich przepływów do tego samego celu (host_dst_gap_cv).
def pair_regularity(flows, group_columns):
    keys = group_columns + ["dst_ip"]
    ordered = flows.sort_values(keys + [START], kind="stable")
    # odstęp przed przepływem; pierwszy przepływ pary nie ma odstępu (NaN), więc okno 4 odstępów,
    # które zahacza o poprzednią parę, też daje NaN i nie miesza par
    gaps = ordered.groupby(keys, sort=False)[START].diff() / 1000
    window = gaps.rolling(PAIR_FLOWS - 1)
    mean = window.mean()
    # CV = odchylenie / średnia; mean.where(mean > 0) zamienia średnią 0 na NaN, żeby nie dzielić przez 0
    cv = window.std(ddof=0) / mean.where(mean > 0)
    cv[mean == 0] = 0.0  # wszystkie przepływy w tej samej milisekundzie = idealnie regularnie
    # NaN (za mało przepływów do tego celu) -> 1, czyli „jak losowy ruch”; reindex wraca do kolejności wejścia
    return cv.fillna(1.0).reindex(flows.index).to_numpy()


# Zwraca kopię tabeli przepływów z pięcioma kolumnami cech kontekstu hosta.
def add_window_features(flows, window_seconds=WINDOW_SECONDS):
    flows = flows.reset_index(drop=True).copy()
    values = {name: np.zeros(len(flows)) for name in WINDOW_FEATURES[:4]}

    group_columns = ["src_ip"]
    if "recording" in flows.columns:
        group_columns = ["recording", "src_ip"]

    # Każdy host osobno, przepływy w kolejności startu. Okno przesuwne: left = pierwszy przepływ, który
    # jeszcze jest w ostatnich 60 s; liczniki celów i portów zmieniamy tylko o to, co weszło i wyszło,
    # więc całość jest liniowa, a nie kwadratowa.
    for _, host_flows in flows.groupby(group_columns, sort=False):
        host_flows = host_flows.sort_values(START, kind="stable")
        rows = host_flows.index.to_numpy()
        times = host_flows[START].to_numpy() / 1000
        destinations = host_flows["dst_ip"].to_numpy()
        ports = host_flows["dst_port"].to_numpy()
        rst_sum = np.cumsum(host_flows["bidirectional_rst_packets"].to_numpy() > 0)  # suma narastająca

        destination_counter = {}
        port_counter = {}
        left = 0
        for current in range(len(rows)):
            add_to_counter(destination_counter, destinations[current])
            add_to_counter(port_counter, ports[current])
            # usuwam z okna przepływy starsze niż 60 s
            while times[current] - times[left] > window_seconds:
                remove_from_counter(destination_counter, destinations[left])
                remove_from_counter(port_counter, ports[left])
                left += 1

            flows_in_window = current - left + 1
            # liczba przepływów z RST w oknie z sumy narastającej: suma do bieżącego minus suma przed oknem
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
