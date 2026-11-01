#!/usr/bin/env python3
"""Etykiety dla zbioru CIC-IDS2017 (Sharafaldin i in. 2018), tą samą regułą co Mininet (label_flows.py).

Wejście:
  - przepływy policzone przez extract_flows.py z nagrań CIC (po jednym pliku .parquet na dzień),
  - ground truth w naszym formacie CSV (features/cic_ground_truth/official.csv), jeden wiersz = jeden atak:
      date          dzień nagrania, np. 2017-07-05
      start, end    początek i koniec ataku w czasie LOKALNYM laboratorium CIC (HH:MM albo HH:MM:SS),
                    tak jak na stronie zbioru; w kodzie dodaję 3 h (czas ADT = UTC-3), bo PCAP-y są w UTC
      attacker_ip   adres atakującego (dla ataków z zewnątrz w nagraniu widać adres po NAT)
      target_ip     adres celu; PUSTE = dowolny cel
      service_port  port usługi celu; PUSTE = dowolny
      protocol      tcp albo udp; PUSTE = dowolny
      cic_label     nazwa ataku w CIC, np. "DoS slowloris"

Wyjście: jeden plik .parquet z kolumnami label, attack_type, source ("cic"), recording (dzień).

    python3 features/label_cic.py --flows data/flows_raw/cic \
        --ground-truth features/cic_ground_truth/official.csv --out data/flows/cic.parquet
"""
import argparse
import csv
from datetime import datetime, timedelta, timezone

from label_flows import OUT_OF_SCOPE, PROTOCOL_NUMBER, label_recordings, save

# Nazwy ataków w CIC -> nasze klasy. Pozostałe dostają poza_zakresem, np. FTP-Patator, Heartbleed,
# Bot (C2 ma być atakiem niewidzianym w treningu). Hulk, GoldenEye i DDoS to HTTP flood na port 80.
CIC_TO_ATTACK_TYPE = {
    "PortScan": "port_scan",
    "SSH-Patator": "ssh_bruteforce",
    "DoS slowloris": "dos_slow",
    "DoS Slowhttptest": "dos_slow",
    "DoS Hulk": "http_flood",
    "DoS GoldenEye": "http_flood",
    "DDoS": "http_flood",
}
HOURS_TO_UTC = 3  # lipiec 2017 w Nowym Brunszwiku: ADT = UTC-3


# Czas lokalny CIC -> sekundy UTC. Koniec obejmuje całą podaną jednostkę: "11:00" to do 11:00:59
# (w nagraniu środy Hulk ma jeszcze ok. 12,5 tys. przepływów w minucie 11:00), a "10:37:49" to do
# 10:37:49,999 (w tej sekundzie serwer zamyka jeszcze 127 połączeń Slowhttptest).
def to_utc_seconds(date, clock, is_end=False):
    extra_seconds = 0
    if is_end:
        extra_seconds = 0.999
    if clock.count(":") == 1:
        clock = clock + ":00"
        if is_end:
            extra_seconds = 59.999
    local = datetime.strptime(f"{date} {clock}", "%Y-%m-%d %H:%M:%S")
    return (local + timedelta(hours=HOURS_TO_UTC)).replace(tzinfo=timezone.utc).timestamp() + extra_seconds


# Czyta ground truth CIC i zamienia każdy wiersz na atak w formacie label_flows.py.
def read_ground_truth(path):
    attacks = []
    with open(path) as file:
        for row in csv.DictReader(file):
            attacks.append({
                "type": CIC_TO_ATTACK_TYPE.get(row["cic_label"], OUT_OF_SCOPE),
                "attacker_ip": row["attacker_ip"],
                "target_ips": [row["target_ip"]] if row["target_ip"] != "" else None,
                "service_port": int(row["service_port"]) if row["service_port"] != "" else None,
                "protocol": PROTOCOL_NUMBER[row["protocol"]] if row["protocol"] != "" else None,
                "start": to_utc_seconds(row["date"], row["start"]),
                "end": to_utc_seconds(row["date"], row["end"], is_end=True),
            })
    return attacks


# Czyta ground truth CIC, etykietuje każde nagranie (dzień) wspólną regułą z label_flows.py
# i zapisuje jeden plik z kolumnami source = "cic" i recording = nazwa dnia.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", required=True, help="katalog z plikami .parquet z extract_flows.py")
    parser.add_argument("--ground-truth", required=True, help="CSV z features/cic_ground_truth/")
    parser.add_argument("--out", required=True, help="wyjściowy plik .parquet")
    args = parser.parse_args()

    attacks = read_ground_truth(args.ground_truth)
    print(f"Ataków w ground truth: {len(attacks)}")
    save(label_recordings(args.flows, attacks, "cic"), args.out)


if __name__ == "__main__":
    main()
