#!/usr/bin/env python3
r"""Etykiety dla GeNIS tą samą regułą co Mininet (label_flows.py).

Ground truth zbioru (genis-ground-truth.csv): start i koniec ataku w sekundach UTC, protokół,
atakujący, cel, port usługi i nazwa ataku. Wynik: jeden plik z kolumnami label, attack_type,
source ("genis") i recording (nazwa nagrania).

    python3 features/label_genis.py --flows data/flows_raw/genis \
        --ground-truth data/datasety/GeNIS/0-info/genis-ground-truth.csv \
        --out data/flows/genis.parquet
"""
import argparse
import csv
import math

from label_flows import OUT_OF_SCOPE, PROTOCOL_NUMBER, label_recordings, save

#nazwy ataków w GeNIS -> nasze klasy. Pozostałe (np. recon-dns, bruteforce-smb, bruteforce-ftp,
#floody UDP/ICMP/push-ack) dostają poza_zakresem i są później usuwane.
GENIS_TO_ATTACK_TYPE = {
    "recon-nmap": "port_scan",
    "bruteforce-ssh": "ssh_bruteforce",
    "dos-slowloris": "dos_slow",
    "dos-hulk": "http_flood",
}


#czyta ground truth i zamienia każdy wiersz na atak w formacie label_flows.py.
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
                #start w GeNIS ma ułamki milisekund, a NFStream podaje start przepływu w pełnych ms:
                #zaokrąglam w dół do ms, żeby pierwszy przepływ ataku (ta sama milisekunda) nie wypadł z okna
                "start": math.floor(float(row["StartTime"]) * 1000) / 1000,
                "end": float(row["LastTime"]),
            })
    return attacks


#czyta ground truth GeNIS, etykietuje każde nagranie wspólną regułą z label_flows.py
#i zapisuje jeden plik z kolumnami source = "genis" i recording = nazwa nagrania.
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
