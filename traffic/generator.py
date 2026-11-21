#!/usr/bin/env python3
"""
-Dla każdego z 13 hostów zapisuje plik zadania (adresy serwerów, ziarno, czas sesji, godzina startu)
-Uruchamia w tym hoście worker.py 
-zwraca słownik host -> proces workera

"""
import json #zapis pliku zadania
import os #składanie sciezek
import subprocess #DEVNULL dla wyjścia workerów

import services #adres serwera/katalog w którym lezy klucz ssh/konto labuser
import profiles # daje BEHAVIOR - lista 13 hostów które generują ruch

# serwery, do których hosty wysyłają ruch normalny; adresy z topology.py (przez services.ip)
# dla każdej z nazw: nazwa serwera -> adres
TARGETS = {name: services.ip(name) for name in ["web", "xweb", "dns", "ssh", "files", "mail"]}

WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker.py") #pełna scieżka do traffic/worker.py

#tworzy słownik zadania i zapisuje go do pliku job_<host>.json w katalogu sesji out - zwraca ścieżkę tego pliku
def write_job(out, host, seed, duration, start_hour):
    job = {
        "host": host.name, "targets": TARGETS, "key": f"{services.LAB}/_client/id_ed25519",
        "user": services.SSH_USER, "seed": seed, "duration": duration,
        "start_hour": start_hour, "log": os.path.join(out, f"traffic_{host.name}.jsonl"),
    }
    path = os.path.join(out, f"job_{host.name}.json") #zapisanie w katalogu sesji
    with open(path, "w") as file:
        json.dump(job, file)
    return path


#zwraca słownik host -> proces workera (run_session.py wstrzymuje po nim generator atakującego)
#Ziarno hosta to napis "<ziarno sesji>/<host>", np. "101/o3" (random.Random z napisu jest deterministyczny).
#Napis nie nakłada się między sesjami (suma ziarna i numeru hosta powtarzałaby sekwencje w różnych sesjach).
def start_workers(net, out, base_seed, duration, start_hour):
    workers = {} #pusty słownik na host -> proces
    for name in sorted(profiles.BEHAVIOR):
        host = net.get(name) #pobiera obiekt hosta z sieci mininetu
        job = write_job(out, host, f"{base_seed}/{name}", duration, start_hour) #zapisuje zadanie z ziarnem
        #wyjście workera na DEVNULL: popen Minineta daje domyślnie potoki, których nikt nie czyta
        #(pełny potok zatrzymałby workera); błędy worker zapisuje do swojego logu
        workers[name] = host.popen(["python3", WORKER, "--job", job], stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL) #uruchamia worker w przestrzeni nazw tego hosta
    return workers
