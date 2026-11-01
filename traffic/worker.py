#!/usr/bin/env python3
"""Generator ruchu normalnego dla jednego hosta (uruchamiany w jego przestrzeni nazw).

Pętla: wylosuj typ sesji wg wag grupy, wykonaj sesję (sekwencja akcji z mikro-opóźnieniami),
odczekaj wykładniczy odstęp między sesjami (w czasie rzeczywistym). IoT ma zamiast
tego heartbeat o stałym odstępie. Każdą akcję loguję do pliku JSONL (do debugowania; etykietą
ruchu normalnego i tak jest "brak ataku w oknie czasowym", nie ten log).

Wywoływany przez generator.py przez host.popen; parametry w pliku JSON (--job).
"""
import argparse
import json
import os
import random
import smtplib #wysylanie poczty z pythona
import subprocess #uruchamianie curl,dig itp
import sys
import threading #osobny watek dla ruchu tla
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__))) #worker czyta ustawienia z profiles
import profiles  #profile zachowania hostów

JOB = {} #zadanie dla hosta z pliku JSON
LOG = None #otwarty plik logu
LOG_LOCK = threading.Lock()  # log piszą dwa wątki (sesje + tło) - blokada aby linie sie nie przeplataly

#dopisuje do traffic_<host>.jsonl: czas, host, akcja, parametry akcji (np. docelowy host, liczba bajtów)
# **kw pozawala dorzucic dowolne pola np. names przy DNS
def log(action, **kw):
    record = {"t": round(time.time(), 3), "host": JOB["host"], "action": action, **kw}
    with LOG_LOCK:
        LOG.write(json.dumps(record) + "\n")
        LOG.flush() # zapisuje od razu do pliku - nawet przy zabitym procesie log jest kompletny

#uruchamia polecenie z limitem czasu i ukrywa jego wyjście (DEVNULL)
#jesli program nie skonczy w limicie np. curl zawisnie na przeciazanoym serwerze w czaie DoS to
#subprocess go zabija i rzuca TimeoutExpired - a my to łapiemy zeby worker pracował dalej
def run(cmd, timeout):
    try:
        subprocess.run(cmd, timeout=timeout, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False) #bład progamu nie przerywa
    except subprocess.TimeoutExpired:
        pass

# pauza "namysłu użytkownika" między akcjami w jednej sesji - losowa z rozkłądu wykłądniczego z serdnia 0,4s
def think(rng):
    time.sleep(rng.expovariate(1.0 / profiles.THINK_TIME_MEAN_S))

#Sesja używana: biuro 55%, deweloper 30%, drukarka 50%
#w 30% przypadków serwer zewnętrzny, 70% wewnetrzny - najpierw strona głowna potem 1-5 plików
#wybranych według popularności Zipf - kazde curl to osobne połączenie TCP na port 80
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
    log("web_browse", target=base)

#Sesja używana:biuro 20%, deweloper 10%, admin 20%, drukarka 50%
# 1-3 rozne nazwy(losuje bez powtórzen) sposród 4 wewnetrznych i 3 zewnętrznych
# każe dig to zapytanie UDP na port 53 do serwera DNS - jedna próba - czekaj najwyżej 2s
def session_dns_lookup(rng):
    targets = JOB["targets"]
    available_names = profiles.DNS_NAMES_INTERNAL + profiles.DNS_NAMES_EXTERNAL
    names = rng.sample(available_names, k=rng.randint(1, 3))
    for name in names:
        run(["dig", "+tries=1", "+time=2", "+short", name, f"@{targets['dns']}"], 4)
        think(rng)
    log("dns_lookup", names=names)

#Sesja używana: biuro 25%
#treść o rozmiarze log-normalnym (mediana ok 400B, 20B - 200KB) - wysyłana przez smtplib do mail:25
#nadawca to np. o1@firma.lab ; blędy są zapisywane do logu jako mail_send_error
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
        log("mail_send", bytes=len(body))
    except Exception as e:
        log("mail_send_error", error=str(e))

#jedno polecenie przez SSH (logowanie kluczem): bez pytania o zaufanie do serwera i o hasło (BatchMode),
#najwyżej 5 s na nawiązanie połączenia
def ssh_command(target, cmd, timeout=12):
    key, user = JOB["key"], JOB["user"]
    run(["ssh", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{user}@{target}", cmd], timeout)

#Sesja używana: deweloper 30%
#2-3 polecenia z SSH_COMMANDS na serwerze ssh, kazde przez osobone połączenie SSH (logowanie kluczem, port 22)
def session_ssh_work(rng):
    targets = JOB["targets"]
    for cmd in rng.sample(profiles.SSH_COMMANDS, k=rng.randint(2, 3)):
        ssh_command(targets["ssh"], cmd)
        think(rng)
    log("ssh_work", target=targets["ssh"])


#Sesja używana: deweloper 30%
#scp jednego losowego pliku z serwera files(port 22) - plik lezy w katalogu serwera WWW: wspolny dysk sprawia, ze
#files tez go widzi - rozmiar transferu jest ciezkoogonowy - plik laduje w /tmp/lab/<host>_dl.bin 
# jest nadpisany przy kolejnym tranferze wiec dysk sie nie zapycha az tak
def session_file_transfer(rng):
    targets = JOB["targets"]
    key, user = JOB["key"], JOB["user"]
    fname = rng.choice(profiles.web_file_names())   # losowy plik = losowy rozmiar transferu
    dest = f"/tmp/lab/{JOB['host']}_dl.bin"
    run(["scp", "-q", "-i", key, "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5", f"{user}@{targets['files']}:/tmp/lab/web/www/{fname}", dest], 30)
    log("file_transfer", target=targets["files"], file=fname)


#Sesja używana: admin 80%
#2-4 różne serwery (ssh, files, web, mail) - na każdym jedno polecenie z krótszym limitem 8s
#to wzorzec admina - wszedl, sprawdzil, wyszedl - na wielu maszynach
def session_ssh_admin(rng):
    targets = JOB["targets"]
    services = [targets["ssh"], targets["files"], targets["web"], targets["mail"]]
    for target in rng.sample(services, k=rng.randint(2, 4)):
        ssh_command(target, rng.choice(profiles.SSH_COMMANDS), timeout=8)
        think(rng)
    log("ssh_admin")


#to jest słownik nazwa sesji na funckje - dzieki niemu wylosowana nazwę wystraczy wywołać jako SESSIONS[kind](rng)
SESSIONS = {
    "web_browse": session_web_browse,
    "dns_lookup": session_dns_lookup,
    "mail_send": session_mail_send,
    "ssh_work": session_ssh_work,
    "file_transfer": session_file_transfer,
    "ssh_admin": session_ssh_admin,
}


#działą w pętli aż do końca sesji 
#losuje typ sesji według wag grupy
# ustala jaka jest teraz godzina doby i z krzywej bierze mnożnik
# średni odstęp od nastepnej sesji = 3600 / (sph * mnożnik) - faktyczny odstep losuje z rozkladu wykladniczego
# i od razu wyznacza chwilę startu następnej sesji (odstęp liczony od startu do startu, nie od końca sesji)
#wykonuje ją - gdyby funkcja rzuciła nieoczekiwany wyjątek zapisuje do session error i idzie dalej
# to jest proces Poisonna - starty sesji pojawiają się niezależnie w losowych odstępach czasu (Paxon i Floyd 1995)
# spi do startu następnej sesji, ale nie dłużej niż do końca sesji (gdy sesja trwała dłużej, następna rusza od razu)
def loop_sessions(rng, group, deadline):
    curve = profiles.daily_curve()
    kinds = list(group["sessions"].keys())
    weights = list(group["sessions"].values())
    base_sessions_per_hour = group["sph"]
    while time.time() < deadline:
        hour = profiles.hour_of_day(time.time() - JOB["start"], JOB["start_hour"])
        sessions_per_hour = max(0.1, base_sessions_per_hour * curve[hour])
        mean_gap = 3600.0 / sessions_per_hour  # sekundy (czas rzeczywisty)
        next_start = time.time() + rng.expovariate(1.0 / mean_gap)
        kind = rng.choices(kinds, weights=weights)[0]
        try:
            SESSIONS[kind](rng)
        except Exception as e:
            log("session_error", kind=kind, error=str(e))
        time.sleep(max(0.0, min(next_start, deadline) - time.time()))

# co 60s curl strony głownej xweb (heartbeat)
# odstęp ma tylko +/- 5% rozrzutu więc jest prawie idealnie regularny - "legalny beaconing"
# IoT nie ma ruchu tła
# Heartbeat o stałym odstępie (sekundy) do xweb - legalny, ale podobny do beaconingu.
def loop_iot(rng, group, deadline):
    targets = JOB["targets"]
    interval = group["heartbeat_s"]
    while time.time() < deadline:
        run(["curl", "-s", "-o", "/dev/null", "--max-time", "5", f"http://{targets['xweb']}/"], 6)
        log("iot_heartbeat", target=targets["xweb"])
        jitter = rng.uniform(-0.05, 0.05) * interval  # niewielki, by nie było idealnie okresowe
        time.sleep(max(0.1, min(interval + jitter, max(0.0, deadline - time.time()))))

#co 30-90s (rozkład równomierny) jedno zapytanie DNS o nazwe wewnętrzną
# w połowie przyppadków dodatkowo curl do xweb - "sprawdzenie aktualizacji"
# to ruch który w firmie idzie zawsze nie zaleznie od tego co robi użytkownik
def background_loop(rng, deadline):
    targets = JOB["targets"]
    while time.time() < deadline:
        run(["dig", "+tries=1", "+time=2", "+short", rng.choice(profiles.DNS_NAMES_INTERNAL),
             f"@{targets['dns']}"], 4)
        if rng.random() < 0.5:
            run(["curl", "-s", "-o", "/dev/null", "--max-time", "5", f"http://{targets['xweb']}/"], 6)
        log("background")
        time.sleep(min(rng.uniform(30, 90), max(0.0, deadline - time.time())))

#Main wczytuje plik zadania do JOB
#rng : własny generator losowy z ziarnem - ziarno to ziarno sesji + numer hosta - więc każdy host losuje inaczej
# zapamiętuje czas startu i liczy koniec (deadline)
# otwiera log w trybie append
#szuka zachowania hosta i grupy hosta
# IOT tylko heartbeat
#zapis worek stop i zamknięcie logu
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
    log("worker_start", behavior=behavior)
    if behavior == "iot":
        loop_iot(rng, group, deadline)
    else:
        # stałe tło w osobnym wątku, równolegle do sesji użytkownika
        background = threading.Thread(target=background_loop,
                                      args=(random.Random(JOB["seed"] + 999), deadline), daemon=True)
        background.start()
        loop_sessions(rng, group, deadline)
        background.join(timeout=5)
    log("worker_stop")
    LOG.close()


if __name__ == "__main__":
    main()
