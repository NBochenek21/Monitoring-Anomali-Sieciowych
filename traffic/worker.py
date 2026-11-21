#!/usr/bin/env python3
"""Ruch normalny jednego hosta: działa w jego przestrzeni nazw przez całą sesję.

W pętli losuje typ sesji i wykonuje ją; następna startuje po losowym (wykładniczym) odstępie od startu poprzedniej.
IoT zamiast sesji wysyła heartbeat co 60 s. Każda akcja trafia do logu traffic_<host>.jsonl.
Etykiety nie biorą się z tego logu, tylko z ground truth ataków.
"""

import argparse
import json
import os
import random
import signal
import smtplib #wysylanie poczty z pythona
import subprocess #uruchamianie curl,dig itp
import sys
import threading #osobny watek dla ruchu tla
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))) #worker czyta ustawienia z profiles
import profiles  #profile zachowania hostów

JOB = {} #zadanie z pliku JSON (adresy serwerów, ziarno, czas sesji)
LOG = None #otwarty plik logu
LOG_LOCK = threading.Lock() #blokada logu, bo piszą do niego dwa wątki (sesje i tło)

#dopisuje do traffic_<host>.jsonl: czas, host, akcja, parametry akcji (np. docelowy host, liczba bajtów)
# **kw pozwala dorzucić dowolne pola np. names przy DNS
def log(action, **kw):
    record = {"t": round(time.time(), 3), "host": JOB["host"], "action": action, **kw}
    with LOG_LOCK:
        if LOG.closed:  #wątek tła może pisać już po zamknięciu logu na końcu main
            return
        LOG.write(json.dumps(record) + "\n")
        LOG.flush() # zapisuje od razu do pliku - nawet przy zabitym procesie log jest kompletny

#uruchamia polecenie z limitem czasu i ukrywa jego wyjście (DEVNULL)
#jeśli program nie skończy w limicie, np. curl zawiśnie na przeciążonym serwerze w czasie DoS, to
#subprocess go zabija i rzuca TimeoutExpired - a my to łapiemy zeby worker pracował dalej
def run(cmd, timeout):
    try:
        # check=False: błąd programu nie przerywa workera
        subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    except subprocess.TimeoutExpired:
        pass

#śpi do podanej chwili w kawałkach po 1 s - po zamrożeniu na czas ataku (SIGSTOP)
#worker wraca do pracy najpóźniej sekundę po odmrożeniu a nie dosypia przerwanego snu
SLEEP_STEP_S = 1.0


def sleep_until(until):
    while True:
        left = until - time.time()
        if left <= 0:
            return
        time.sleep(min(left, SLEEP_STEP_S))


#krótka przerwa między akcjami w sesji, losowa, średnio 0,4 s
def think(rng):
    sleep_until(time.time() + rng.expovariate(1.0 / profiles.THINK_TIME_MEAN_S))

# sesja WWW: 70% serwer firmowy, 30% "internet"; strona główna i 1-5 plików wybranych wg Zipfa
def session_web_browse(rng):
    targets = JOB["targets"]
    base = targets["xweb"] if rng.random() < 0.3 else targets["web"]
    run(["curl", "-s", "-o", "/dev/null", "--max-time", "10", f"http://{base}/"], 12)
    if base == targets["web"]:
        names, weights = profiles.web_file_names(), profiles.zipf_weights()
    else:
        names = profiles.web_file_names(profiles.XWEB_FILE_COUNT)
        weights = profiles.zipf_weights(profiles.XWEB_FILE_COUNT)
    for _ in range(rng.randint(1, 5)):
        think(rng)
        fname = rng.choices(names, weights=weights)[0]
        run(["curl", "-s", "-o", "/dev/null", "--max-time", "20", f"http://{base}/{fname}"], 22)
    return "web_browse", {"target": base}

# sesja DNS: 1-3 różne nazwy (firmowe albo "internetowe") przez dig do firmowego DNS
def session_dns_lookup(rng):
    targets = JOB["targets"]
    available_names = profiles.DNS_NAMES_INTERNAL + profiles.DNS_NAMES_EXTERNAL
    names = rng.sample(available_names, k=rng.randint(1, 3))
    for name in names:
        run(["dig", "+tries=1", "+time=2", "+short", name, f"@{targets['dns']}"], 4)
        think(rng)
    return "dns_lookup", {"names": names}

#Sesja z grupy biuro (wagi w profiles.GROUPS)
#treść o rozmiarze log-normalnym (mediana ok 400B, 20B - 200KB) - wysyłana przez smtplib do mail:25
#nadawca to np. o1@firma.lab ; błędy są zapisywane do logu jako mail_send_error
def session_mail_send(rng):
    targets = JOB["targets"]
    size = int(rng.lognormvariate(6.0, 1.0))  # treść maila: log-normalnie
    text = "x" * max(20, min(size, 200000))
    # treść w liniach po 76 znaków jak w prawdziwej poczcie; serwer odrzuca linie dłuższe niż 1000 (RFC 5321)
    body = "Subject: raport\n\n" + "\n".join(text[i:i + 76] for i in range(0, len(text), 76))
    try:
        smtp = smtplib.SMTP(targets["mail"], 25, timeout=8)
        smtp.sendmail(f"{JOB['host']}@firma.lab", ["mbox@firma.lab"], body)
        smtp.quit()
        return "mail_send", {"bytes": len(body)}
    except Exception as e:
        return "mail_send_error", {"error": str(e)}

#jedno polecenie przez SSH (logowanie kluczem): bez pytania o zaufanie do serwera i o hasło (BatchMode),
#najwyżej 5 s na nawiązanie połączenia
def ssh_command(target, cmd, timeout=12):
    key, user = JOB["key"], JOB["user"]
    run(["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{user}@{target}", cmd], timeout)

#Sesja z grupy deweloper (wagi w profiles.GROUPS)
#2-3 polecenia z SSH_COMMANDS na serwerze ssh, każde przez osobne połączenie SSH (logowanie kluczem, port 22)
def session_ssh_work(rng):
    targets = JOB["targets"]
    for cmd in rng.sample(profiles.SSH_COMMANDS, k=rng.randint(2, 3)):
        ssh_command(targets["ssh"], cmd)
        think(rng)
    return "ssh_work", {"target": targets["ssh"]}


#Sesja z grupy deweloper (wagi w profiles.GROUPS)
#scp jednego losowego pliku z serwera files (port 22) - plik leży w katalogu serwera WWW: wspólny dysk sprawia, że
#files też go widzi - rozmiar transferu jest ciężkoogonowy - plik ląduje w /tmp/lab/<host>_dl.bin
# i jest nadpisywany przy kolejnym transferze, więc dysk się nie zapycha
def session_file_transfer(rng):
    targets = JOB["targets"]
    key, user = JOB["key"], JOB["user"]
    fname = rng.choice(profiles.web_file_names())   # losowy plik = losowy rozmiar transferu
    dest = f"/tmp/lab/{JOB['host']}_dl.bin"
    run(["scp", "-q", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{user}@{targets['files']}:/tmp/lab/web/www/{fname}",
         dest], 30)
    return "file_transfer", {"target": targets["files"], "file": fname}


#Sesja z grupy admin (wagi w profiles.GROUPS)
#2-4 różne serwery (ssh, files, web, mail) - na każdym jedno polecenie z krótszym limitem 8s
#to wzorzec admina - wszedł, sprawdził, wyszedł - na wielu maszynach
#sshd działa na wszystkich czterech serwerach (env/services.py start_services)
def session_ssh_admin(rng):
    targets = JOB["targets"]
    services = [targets["ssh"], targets["files"], targets["web"], targets["mail"]]
    for target in rng.sample(services, k=rng.randint(2, 4)):
        ssh_command(target, rng.choice(profiles.SSH_COMMANDS), timeout=8)
        think(rng)
    return "ssh_admin", {}


#to jest słownik nazwa sesji -> funkcja - dzięki niemu wylosowaną nazwę wystarczy wywołać jako SESSIONS[kind](rng)
#każda funkcja sesji zwraca (akcja, pola do logu); zapis do logu robi loop_sessions razem z chwilą startu
SESSIONS = {
    "web_browse": session_web_browse,
    "dns_lookup": session_dns_lookup,
    "mail_send": session_mail_send,
    "ssh_work": session_ssh_work,
    "file_transfer": session_file_transfer,
    "ssh_admin": session_ssh_admin,
}


#działa w pętli aż do końca sesji
#losuje typ sesji według wag grupy
# ustala jaka jest teraz godzina doby i z krzywej bierze mnożnik
# średni odstęp do następnej sesji = 3600 / (sph * mnożnik) - faktyczny odstęp losuje z rozkładu wykładniczego
# i od razu wyznacza chwilę startu następnej sesji (odstęp liczony od startu do startu, nie od końca sesji)
#wykonuje ją - gdyby funkcja rzuciła nieoczekiwany wyjątek, zapisuje session_error i idzie dalej
# to jest proces Poissona - starty sesji pojawiają się niezależnie w losowych odstępach czasu
# spi do startu następnej sesji, ale nie dłużej niż do końca sesji (gdy sesja trwała dłużej, następna rusza od razu)
# rekord w logu ma pole start (chwila startu sesji): stats/summarize.py bada odstępy między startami,
# bo to je losuje proces Poissona (t to chwila zapisu, czyli koniec sesji)
def loop_sessions(rng, group, deadline):
    curve = profiles.daily_curve()
    kinds = list(group["sessions"].keys())
    weights = list(group["sessions"].values())
    base_sessions_per_hour = group["sph"]
    while time.time() < deadline:
        hour = profiles.hour_of_day(time.time() - JOB["start"], JOB["start_hour"])
        #max(0.1) to tylko zabezpieczenie przed zerową stawką; przy obecnych wagach nigdy nie działa
        sessions_per_hour = max(0.1, base_sessions_per_hour * curve[hour])
        mean_gap = 3600.0 / sessions_per_hour  # sekundy (czas rzeczywisty)
        started = time.time()
        next_start = started + rng.expovariate(1.0 / mean_gap)
        kind = rng.choices(kinds, weights=weights)[0]
        try:
            action, fields = SESSIONS[kind](rng)
            log(action, start=round(started, 3), **fields)
        except Exception as e:
            log("session_error", kind=kind, start=round(started, 3), error=str(e))
        sleep_until(min(next_start, deadline))

# co 60 s curl strony głównej xweb (heartbeat)
# odstęp ma tylko +/- 5% rozrzutu, więc jest prawie idealnie regularny - "legalny beaconing"
# IoT nie ma ruchu tła
def loop_iot(rng, group, deadline):
    targets = JOB["targets"]
    interval = group["heartbeat_s"]
    while time.time() < deadline:
        #błąd jednego heartbeatu nie może po cichu zakończyć pętli: zapis do logu i następna próba
        try:
            run(["curl", "-s", "-o", "/dev/null", "--max-time", "5", f"http://{targets['xweb']}/"], 6)
            log("iot_heartbeat", target=targets["xweb"])
        except Exception as error:
            log("iot_error", error=repr(error))
        jitter = rng.uniform(-0.05, 0.05) * interval  # niewielki, by nie było idealnie okresowe
        sleep_until(min(time.time() + max(0.1, interval + jitter), deadline))

#co 30-90 s (rozkład równomierny) jedno zapytanie DNS o nazwę wewnętrzną
# w połowie przypadków dodatkowo curl do xweb - "sprawdzenie aktualizacji"
# to ruch, który w firmie idzie zawsze, niezależnie od tego, co robi użytkownik
def background_loop(rng, deadline):
    targets = JOB["targets"]
    while time.time() < deadline:
        #błąd nie może po cichu zakończyć wątku tła: zapis do logu i następna iteracja
        try:
            run(["dig", "+tries=1", "+time=2", "+short", rng.choice(profiles.DNS_NAMES_INTERNAL),
                 f"@{targets['dns']}"], 4)
            if rng.random() < 0.5:
                run(["curl", "-s", "-o", "/dev/null", "--max-time", "5", f"http://{targets['xweb']}/"], 6)
            log("background")
        except Exception as error:
            log("background_error", error=repr(error))
        sleep_until(min(time.time() + rng.uniform(30, 90), deadline))

#Main wczytuje plik zadania do JOB
#rng: własny generator losowy z ziarnem "<ziarno sesji>/<host>" (generator.py) - każdy host losuje inaczej
# zapamiętuje czas startu i liczy koniec (deadline)
# otwiera log (run_session.py usuwa stare logi na starcie sesji)
#szuka zachowania hosta i grupy hosta
# IoT tylko heartbeat
#SIGTERM od run_session.py kończy pętlę przez SystemExit, więc worker_stop trafia do logu także wtedy
def main():
    global JOB, LOG
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--job", required=True, help="plik JSON z zadaniem dla hosta")
    args = parser.parse_args()
    with open(args.job) as f:
        JOB = json.load(f)

    rng = random.Random(JOB["seed"])
    JOB["start"] = time.time()
    deadline = JOB["start"] + JOB["duration"]
    LOG = open(JOB["log"], "a")

    behavior = profiles.BEHAVIOR[JOB["host"]]
    group = profiles.GROUPS[behavior]
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log("worker_start", behavior=behavior)
    try:
        if behavior == "iot":
            loop_iot(rng, group, deadline)
        else:
            # stałe tło w osobnym wątku, równolegle do sesji użytkownika
            background = threading.Thread(target=background_loop,
                                          args=(random.Random(f"{JOB['seed']}/tlo"), deadline), daemon=True)
            background.start()
            loop_sessions(rng, group, deadline)
            background.join(timeout=5)
    finally:
        log("worker_stop")
        with LOG_LOCK:  #pod blokadą, żeby wątek tła nie pisał w trakcie zamykania
            LOG.close()


if __name__ == "__main__":
    main()
