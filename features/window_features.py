#!/usr/bin/env python3
"""Cechy kontekstu hosta: co host źródłowy robił przed danym przepływem.

Czas przepływu to chwila jego KOŃCA (bidirectional_last_seen_ms), czyli chwila, w której eksporter
przepływów (NFStream, sonda) oddaje gotowy rekord. Wtedy zapada decyzja o przepływie i wtedy znane
są tylko przepływy, które już się skończyły. Porządek po starcie wpuszczałby do kontekstu długie
przepływy, które zaczęły się wcześniej, ale kończą później (look-ahead: 43% okien w danych CIC).

Dla każdego przepływu liczę, patrząc tylko wstecz (od końca przepływu 60 s do tyłu, razem z nim):
  host_flows_60s         - liczba przepływów tego hosta,
  host_destinations_60s  - liczba różnych adresów docelowych,
  host_ports_60s         - liczba różnych portów docelowych,
  host_rst_share_60s     - odsetek przepływów z flagą RST,
oraz regularność połączeń do tego samego celu:
  host_dst_gap_cv        - zmienność odstępów między końcami 5 ostatnich przepływów tego hosta do tego
                           samego adresu docelowego: odchylenie / średnia (blisko 0 = bardzo regularnie,
                           jak beacon C2 albo heartbeat IoT; 1 = za mało przepływów, by to ocenić).
                           Bez limitu 60 s, bo beacon co ok. 45 s ma w 60 s najwyżej 2 przepływy.
                           Regularność komunikacji C2 bada się dla pary klient-serwer (Oprea i in. 2015).

Wszystko liczę osobno w każdym nagraniu (kolumna recording w zbiorach publicznych), żeby nie łączyć
przepływów z różnych dni. Patrzę tylko wstecz, więc cechy są dostępne w chwili końca przepływu.
Cechy trzeba liczyć na pełnych danych, zanim wybierze się próbkę do treningu.

Tu jest też window_rows: okno 8 ostatnich zakończonych przepływów hosta dla FlowTransformera,
liczone tak samo (na pełnych danych, tylko wstecz, po końcu przepływu).

Tabela bez kolumny końca (małe tabele w testach) jest porządkowana po starcie.
"""
import numpy as np

WINDOW_SECONDS = 60
PAIR_FLOWS = 5  # ile ostatnich przepływów do tego samego celu bierze regularność (4 odstępy)

WINDOW_FEATURES = ["host_flows_60s", "host_destinations_60s", "host_ports_60s",
                   "host_rst_share_60s", "host_dst_gap_cv"]
START = "bidirectional_first_seen_ms"
END = "bidirectional_last_seen_ms"


# Kolumna czasu, po której porządkuję przepływy: koniec, a gdy go nie ma - start.
def time_column(flows):
    return END if END in flows.columns else START


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
    when = time_column(flows)
    ordered = flows.sort_values(keys + [when, START], kind="stable")
    # odstęp przed przepływem; pierwszy przepływ pary nie ma odstępu (NaN), więc okno 4 odstępów,
    # które zahacza o poprzednią parę, też daje NaN i nie miesza par
    gaps = ordered.groupby(keys, sort=False)[when].diff() / 1000
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

    # Każdy host osobno, przepływy w kolejności końca. Okno przesuwne: left = pierwszy przepływ, który
    # jeszcze jest w ostatnich 60 s; liczniki celów i portów zmieniamy tylko o to, co weszło i wyszło,
    # więc całość jest liniowa, a nie kwadratowa.
    when = time_column(flows)
    for _, host_flows in flows.groupby(group_columns, sort=False):
        host_flows = host_flows.sort_values([when, START], kind="stable")
        rows = host_flows.index.to_numpy()
        times = host_flows[when].to_numpy() / 1000
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


# Okno FlowTransformera: dla każdego przepływu z rows numery wierszy jego okna, czyli `size` ostatnich
# zakończonych przepływów TEGO SAMEGO hosta (z nim samym na końcu), w kolejności końca; -1 = brak przepływu
# (okno uzupełniane zerami). Historię biorę z całej tabeli flows (także z przepływów attempted
# i sprzed podziału w czasie), jak przy cechach kontekstu; okna powstają tylko dla rows.
# flows: tabela z indeksem 0..n-1, rows: numery wierszy. Zwraca tablicę (len(rows), size).
def window_rows(flows, rows, size):
    host_keys = flows["src_ip"].astype(str).to_numpy()
    if "recording" in flows.columns:  # zbiory publiczne: ten sam adres w różnych nagraniach to różne hosty
        host_keys = flows["recording"].astype(str).to_numpy() + "/" + host_keys
    # kolejność: host, a w nim czas końca (przy równym końcu start); positions[k] = wiersz, który
    # w tej kolejności jest k-ty. lexsort sortuje po ostatnim kluczu najpierw.
    positions = np.lexsort((flows[START].to_numpy(), flows[time_column(flows)].to_numpy(), host_keys))
    rank = np.empty(len(flows), dtype="int64")
    rank[positions] = np.arange(len(flows))
    sorted_hosts = host_keys[positions]
    # pierwsza pozycja bloku każdego hosta (dla każdej pozycji w kolejności)
    new_host = np.r_[True, sorted_hosts[1:] != sorted_hosts[:-1]]
    host_start = np.maximum.accumulate(np.where(new_host, np.arange(len(flows)), 0))
    current = rank[np.asarray(rows)]
    window = current[:, None] + np.arange(-size + 1, 1)  # pozycje size ostatnich przepływów
    inside = window >= host_start[current][:, None]       # tylko przepływy tego samego hosta
    return np.where(inside, positions[np.clip(window, 0, None)], -1)
