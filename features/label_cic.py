#!/usr/bin/env python3
r"""Etykiety dla CIC-IDS2017 tą samą regułą co Mininet (label_flows.py).

Ground truth w CSV (features/cic_ground_truth/official.csv): dzień, start i koniec w czasie lokalnym
laboratorium CIC (dodaję 3 h, bo pcap jest w UTC), atakujący, cel, port, protokół, nazwa ataku w CIC.
Okna to harmonogram ze strony zbioru (UNB CIC) poprawiony według CNS2022 (Liu i in. 2022,
https://intrusion-detection.distrinet-research.be/CNS2022/CICIDS2017.html): m.in. Slowhttptest, Hulk
i SSH-Patator trwają do końca okien CNS2022, a koniec okna obejmuje całą podaną minutę albo sekundę.
Nazwa official.csv znaczy tylko "harmonogram ze strony zbioru", nie oryginalne etykiety CSV z CIC.
Wynik: jeden plik z kolumnami label, attack_type, source ("cic") i recording (dzień).

    python3 features/label_cic.py --flows data/flows_raw/cic \
        --ground-truth features/cic_ground_truth/official.csv \
        --out data/flows/cic.parquet
"""
import argparse
import csv
import os
from datetime import datetime, timedelta, timezone

from label_flows import OUT_OF_SCOPE, PROTOCOL_NUMBER, label_recordings, save

#nazwy ataków w CIC -> nasze klasy. Pozostałe dostają poza_zakresem, np. FTP-Patator, Heartbleed,
#bot (C2 ma być atakiem niewidzianym w treningu). Hulk, GoldenEye i DDoS to HTTP flood na port 80.
CIC_TO_ATTACK_TYPE = {
    "PortScan": "port_scan",
    "SSH-Patator": "ssh_bruteforce",
    "DoS slowloris": "dos_slow",
    "DoS Slowhttptest": "dos_slow",
    "DoS Hulk": "http_flood",
    "DoS GoldenEye": "http_flood",
    "DDoS": "http_flood",
}
HOURS_TO_UTC = 3  #lipiec 2017 w Nowym Brunszwiku: ADT = UTC-3


#czas lokalny CIC -> sekundy UTC; koniec obejmuje całą minutę albo sekundę ("11:00" = do 11:00:59)
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


#czyta ground truth CIC i zamienia każdy wiersz na atak w formacie label_flows.py.
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


#czyta ground truth CIC, etykietuje każde nagranie (dzień) wspólną regułą z label_flows.py
#i zapisuje jeden plik z kolumnami source = "cic" i recording = nazwa dnia.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", required=True, help="katalog z plikami .parquet z extract_flows.py")
    parser.add_argument("--ground-truth", required=True, help="CSV z features/cic_ground_truth/")
    parser.add_argument("--out", required=True, help="wyjściowy plik .parquet")
    args = parser.parse_args()

    #czwartek (ataki web i infiltracja) jest poza zakresem i nie ma go w ground truth, więc jego ataki
    #dostałyby etykietę normal - dlatego nagranie czwartku przerywa program
    thursday = sorted(name for name in os.listdir(args.flows)
                      if name.endswith(".parquet") and "thursday" in name.lower())
    if thursday:
        raise SystemExit(f"Nagranie czwartku poza zakresem (brak okien ataków w ground truth): {thursday}. "
                         f"Usuń je z {args.flows} przed etykietowaniem.")

    attacks = read_ground_truth(args.ground_truth)
    print(f"Ataków w ground truth: {len(attacks)}")
    save(label_recordings(args.flows, attacks, "cic"), args.out)


if __name__ == "__main__":
    main()
