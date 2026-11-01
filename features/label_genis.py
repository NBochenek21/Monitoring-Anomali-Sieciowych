#!/usr/bin/env python3
"""Etykiety dla zbioru GeNIS (Silva i in., Data in Brief 2025), tą samą regułą co Mininet (label_flows.py).

Wejście:
  - przepływy policzone przez extract_flows.py z nagrań GeNIS (pliki .parquet, po jednym na nagranie),
  - plik ground truth zbioru: genis-ground-truth.csv.

Wyjście: jeden plik .parquet ze wszystkimi przepływami GeNIS i kolumnami label, attack_type
(normal, port_scan, ssh_bruteforce, dos_slow, http_flood, poza_zakresem, attempted),
source ("genis") i recording (nazwa nagrania, np. "attack-dos-hulk").

Jak wygląda ground truth GeNIS (jeden wiersz = jeden atak):
  StartTime, LastTime  początek i koniec ataku (sekundy od 1970, czas UTC)
  Proto                protokół: tcp, udp, icmp; PUSTE = dowolny
  SrcAddr              adres atakującego (w GeNIS zawsze kończy się na .99)
  Sport                port atakującego; PUSTE = dowolny (nie używam go)
  DstAddr              adres celu; PUSTE = dowolny cel (np. skan całej podsieci)
  Dport                port usługi celu (np. 22 dla SSH); PUSTE = dowolny
  Label                nazwa ataku w GeNIS

    python3 features/label_genis.py \
        --flows data/flows_raw/genis \
        --ground-truth data/datasety/GeNIS/0-info/genis-ground-truth.csv \
        --out data/flows/genis.parquet
"""
import argparse
import csv
import math

from label_flows import OUT_OF_SCOPE, PROTOCOL_NUMBER, label_recordings, save

# Nazwy ataków w GeNIS -> nasze klasy. Pozostałe (np. recon-dns, bruteforce-smb, bruteforce-ftp,
# floody UDP/ICMP/push-ack) dostają poza_zakresem i są później usuwane.
GENIS_TO_ATTACK_TYPE = {
    "recon-nmap": "port_scan",
    "bruteforce-ssh": "ssh_bruteforce",
    "dos-slowloris": "dos_slow",
    "dos-hulk": "http_flood",
}


# Czyta ground truth i zamienia każdy wiersz na atak w formacie label_flows.py.
def read_ground_truth(path):
    attacks = []
    with open(path) as file:
        for row in csv.DictReader(file):
            attacks.append({
                "type": GENIS_TO_ATTACK_TYPE.get(row["Label"], OUT_OF_SCOPE),
                "attacker_ip": row["SrcAddr"],
                "target_ips": [row["DstAddr"]] if row["DstAddr"] != "" else None,
                "service_port": int(row["Dport"]) if row["Dport"] != "" else None,
                "protocol": PROTOCOL_NUMBER[row["Proto"]] if row["Proto"] != "" else None,
                # start w GeNIS ma ułamki milisekund, a NFStream podaje start przepływu w pełnych ms:
                # zaokrąglam w dół do ms, żeby pierwszy przepływ ataku (ta sama milisekunda) nie wypadł z okna
                "start": math.floor(float(row["StartTime"]) * 1000) / 1000,
                "end": float(row["LastTime"]),
            })
    return attacks


# Czyta ground truth GeNIS, etykietuje każde nagranie wspólną regułą z label_flows.py
# i zapisuje jeden plik z kolumnami source = "genis" i recording = nazwa nagrania.
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--flows", required=True, help="katalog z plikami .parquet z extract_flows.py")
    parser.add_argument("--ground-truth", required=True, help="genis-ground-truth.csv")
    parser.add_argument("--out", required=True, help="wyjściowy plik .parquet")
    args = parser.parse_args()

    attacks = read_ground_truth(args.ground_truth)
    print(f"Ataków w ground truth: {len(attacks)}")
    save(label_recordings(args.flows, attacks, "genis"), args.out)


if __name__ == "__main__":
    main()
