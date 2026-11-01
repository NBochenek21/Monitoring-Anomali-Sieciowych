#!/usr/bin/env python3
"""Uruchamianie generatora ruchu normalnego: po jednym workerze w każdym hoście użytkownika.

1. Stawia sieć topology.build i usługi services.start_services
2. włącza nagrywania na r0
3. woła generator.start_workers - od tej chwili w sieci płynie ruch normalny
4. w trakcie sesji uruchamia ataki i na czas każdego wstrzymuje workera na hoscie atakujacym
5. na końcu zatrzymuje workery, nagrywanie usługi i siec

"""
import json #zapis pliku zadania
import os #składanie sciezek

import services #adres serwera/katalog w którym lezy klucz ssh/konto labuser
import profiles # daje BEHAVIOR - lista 13 hostów które generują ruch

# serwery, do których hosty wysyłają ruch normalny; adresy z topology.py (przez services.ip)
TARGETS = {name: services.ip(name) for name in ["web", "xweb", "dns", "ssh", "files", "mail"]}# dla każdej z nazw tworzy nazwa -> adres

WORKER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "worker.py") #pełna scieżka do traffic/worker.py

#towrzy słosnik zadania i zapisuje go do pliku job_<host>.json w katalogu sesji out - zwraca sciezke tego pliku
def write_job(out, host, seed, duration, start_hour):
    job = {
        "host": host.name, "targets": TARGETS, "key": f"{services.LAB}/_client/id_ed25519",
        "user": services.SSH_USER, "seed": seed, "duration": duration,
        "start_hour": start_hour, "log": os.path.join(out, f"traffic_{host.name}.jsonl"),
    }
    path = os.path.join(out, f"job_{host.name}.json")
    with open(path, "w") as file:
        json.dump(job, file)
    return path


#zwraca słownik host -> proces workera (run_session.py wstrzymuje po nim generator atakującego)
def start_workers(net, out, base_seed, duration, start_hour):
    workers = {} #pusty słownik na host -> proces
    for i, name in enumerate(sorted(profiles.BEHAVIOR)): #ustawia alfabetycznie i przypisuje numer i
        host = net.get(name) #pobiera obiekt hosta z sieci mininetu
        job = write_job(out, host, base_seed + i, duration, start_hour) #zapisauje zadanie z ziarnem
        workers[name] = host.popen(["python3", WORKER, "--job", job]) #uruchamia worker w przestrzeni nazw tego hosta
    return workers
