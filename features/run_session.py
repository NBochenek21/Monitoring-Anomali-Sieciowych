#!/usr/bin/env python3
"""Nagranie sesji: ruch normalny + ataki jednocześnie, capture na r0.

Stawia topologię i usługi, uruchamia generator ruchu w tle, w trakcie odpala wybrane ataki
(orkiestrator), a wszystko nagrywa na r0 do capture.pcap. Produkuje komplet wejścia do potoku:
  <out>/capture.pcap          - ruch (normalny + ataki)
  <out>/ground_truth.jsonl    - okna ataków (do etykietowania)
  <out>/traffic_*.jsonl       - logi generatora (kontrola realizmu)

To narzędzie służy też do właściwych sesji M0–M6. Następny krok to extract_flows.py + label_flows.py.

    python3 features/run_session.py --duration 3600 --attacks all --start-hour 8 --seed 101 --out /root/sessions/M1
    python3 features/run_session.py --duration 900 --attacks A2_ssh_bruteforce A4_http_flood --out /root/test
Sesja z atakami musi trwać co najmniej WARMUP_S + END_MARGIN_S + MIN_GAP_S (560 s).
Kod wyjścia 2 oznacza przerwę albo cofnięcie czasu w nagraniu: sesję trzeba nagrać ponownie
(record_all.sh wtedy jej nie przetwarza).
"""
import glob
import argparse
import os
import random
import signal
import subprocess
import sys
import time

ENV = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "env"))
TRAFFIC = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "traffic"))
ATTACKS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "attacks"))
for d in (ENV, TRAFFIC, ATTACKS):
    sys.path.insert(0, d)

from mininet.log import setLogLevel  # noqa: E402

import topology  # noqa: E402
import services  # noqa: E402
import generator  # noqa: E402
import orchestrator  # noqa: E402


# --- Harmonogram ataków w sesji (decyzja własna; opis w Notion, strona „Praca inżynierska: blueprint”, sekcja 6.5) ---
# Ataki rozkładam na całą sesję (nie wszystkie na początku), każdy scenariusz 3-5 razy,
# z kilkuminutowym odstępem. Konkretne wartości są moją decyzją; łatwo je stroić tutaj.
WARMUP_S = 20          # czysty ruch normalny na starcie, zanim ruszą ataki
END_MARGIN_S = 420     # ogon ruchu normalnego na końcu, bez nowych ataków; dłuższy niż najdłuższy atak
                       # (Z1: 7 beaconów, 6 odstępów po 45 s ±25% i jitter ±20%, czyli najwyżej
                       # 6 × 45 × 1,25 × 1,2 = 405 s), żeby atak kończył się przed końcem sesji
MIN_GAP_S = 120        # docelowy minimalny odstęp między startami kolejnych ataków
REPEATS_MIN, REPEATS_MAX = 3, 5   # ile razy każdy scenariusz na sesję (ile się zmieści)
QUIET_AFTER_ATTACK_S = 60  # co najmniej tyle ciszy po ataku = długość okna cech hosta (window_features),
                           # żeby okno jednego ataku nie obejmowało poprzedniego (np. A3 i A4 z tego samego atk)
MAX_CAPTURE_GAP_S = 120    # dłuższa przerwa bez pakietów = maszyna WSL stała (uśpienie, skok zegara);
                           # ruch tła idzie co 30-90 s z każdego hosta, więc normalnie to się nie zdarza
ROTATION = ["o3", "d2", "o5"]  # rotacja roli zainfekowanej stacji wewnętrznej (pick_attacker)


# Jeden przebieg po nagraniu: liczba pakietów, największa przerwa między pakietami [s]
# i czy czas się cofnął (o więcej niż 1 s; drobne cofnięcia to zwykła kolejność pakietów).
def capture_summary(pcap):
    proc = subprocess.Popen([topology.TCPDUMP, "-r", pcap, "-nn", "-tt"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, text=True)
    packets, max_gap, went_back, previous = 0, 0.0, False, None
    for line in proc.stdout:
        timestamp = float(line.split(" ", 1)[0])
        if previous is not None:
            max_gap = max(max_gap, timestamp - previous)
            went_back = went_back or timestamp - previous < -1.0
        previous = timestamp
        packets += 1
    proc.wait()
    return packets, max_gap, went_back


# Wysyła sygnał do workera i jego procesów potomnych (curl, ssh, scp, dig). Worker startuje przez
# mnexec -d (własna sesja, więc i własna grupa procesów), dlatego killpg obejmuje też polecenie,
# które właśnie wykonuje. Gdy worker nie jest liderem grupy, sygnał idzie tylko do niego - inaczej
# killpg mógłby zatrzymać grupę, w której jest ten skrypt.
def signal_worker(proc, sig):
    if os.getpgid(proc.pid) == proc.pid:
        os.killpg(proc.pid, sig)
    else:
        os.kill(proc.pid, sig)


# Rozkłada ataki na całą sesję i zwraca listę (czas_startu_s, spec) w kolejności czasu.
#
# Każdy scenariusz dostaje co najmniej jedno wystąpienie (pokrycie), a jeśli sesja jest dość
# długa - 3-5 (tyle, ile zmieści się przy odstępie MIN_GAP_S). Ataki i tak idą po kolei
# (run_attack blokuje), więc okna się nie nakładają; krótka sesja testowa dostaje mniej powtórzeń.
def plan_attack_schedule(specs, duration, rng):
    usable = max(1.0, duration - WARMUP_S - END_MARGIN_S)
    capacity = max(len(specs), int(usable // MIN_GAP_S))   # ile wystąpień w ogóle się zmieści
    occurrences = list(specs)                              # po jednym z każdego scenariusza
    extra = [spec for spec in specs for _ in range(rng.randint(REPEATS_MIN, REPEATS_MAX) - 1)]
    rng.shuffle(extra)
    occurrences += extra[:max(0, capacity - len(specs))]   # dołóż powtórzenia, ile wejdzie
    rng.shuffle(occurrences)
    slot = usable / len(occurrences)
    schedule = []
    for i, spec in enumerate(occurrences):
        start = WARMUP_S + i * slot + rng.uniform(0, slot * 0.5)  # losowo w pierwszej połowie slotu
        schedule.append((start, spec))
    return schedule


# Atakujący dla wystąpienia: --attacker ma pierwszeństwo; atk dla ataków z zewnątrz;
# dla ataków z sieci wewnętrznej rotacja o3 -> d2 -> o5 (kolejny atak wewnętrzny = inny host).
def pick_attacker(spec, internal_index, override):
    if override:
        return override
    if spec["attacker"] == "atk":
        return "atk"
    return ROTATION[internal_index % len(ROTATION)]


# Zwraca kopię spec z lekko zmienionymi parametrami, żeby kolejne wystąpienia tego samego ataku
# nie były identyczne. Zmieniają się (±15%): A2 rate_limit_s; A3 connections i duration;
# A4 duration i rps; Z1 interval (±25%). A1 i pozostałe parametry (wątki, tryby, zakresy portów,
# rate i interval slowhttptest, count i jitter beaconu) są stałe. Narzędzia, które same coś losują (jitter beaconów,
# ścieżki floodu), dostają ziarno z rng sesji, więc nagranie z tym samym --seed losuje to samo;
# ziarno trafia też do params w ground truth.
def vary_params(spec, rng):
    # wartość pomnożona przez losowy czynnik z przedziału [1 - frac, 1 + frac]
    def jitter(value, frac=0.15):
        return value * rng.uniform(1 - frac, 1 + frac)

    params = dict(spec["params"])
    attack_type = spec["type"]
    if attack_type == "ssh_bruteforce":
        params["rate_limit_s"] = round(jitter(params.get("rate_limit_s", 0.3)), 2)
    elif attack_type == "dos_slow":
        params["connections"] = max(1, int(jitter(params["connections"])))
        params["duration"] = max(1, int(jitter(params["duration"])))
    elif attack_type == "http_flood":
        params["duration"] = max(1, int(jitter(params["duration"])))
        params["rps"] = max(1, int(jitter(params["rps"])))
        params["seed"] = rng.randrange(10**6)
    elif attack_type == "c2_beaconing":
        params["interval"] = round(jitter(params["interval"], 0.25), 1)
        params["seed"] = rng.randrange(10**6)
    new_spec = dict(spec)
    new_spec["params"] = params
    return new_spec


# Cała sesja: sieć i usługi, nagrywanie na r0, ruch normalny we wszystkich hostach, ataki według
# harmonogramu, na końcu sprzątanie i podsumowanie nagrania. Blok finally sprząta też po błędzie
# albo Ctrl+C, żeby w WSL nie zostały procesy Minineta ani usługi.
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--duration", type=int, default=300, help="czas sesji [s rzeczywiste]")
    parser.add_argument("--out", required=True)
    parser.add_argument("--attacks", nargs="*", default=["all"],
                        help="nazwy scenariuszy albo 'all'; 'none' = bez ataków")
    parser.add_argument("--start-hour", type=int, default=8)
    parser.add_argument("--attacker", default=None, help="nadpisz atakującego dla wszystkich scenariuszy")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Uruchom jako root.")

    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    pcap = os.path.join(out, "capture.pcap")
    # świeży ground truth dla tej sesji
    gt = os.path.join(out, "ground_truth.jsonl")
    if os.path.exists(gt):
        os.remove(gt)
    # stare logi generatora z poprzedniego uruchomienia w tym katalogu (worker pisałby dalej do nich)
    for old_log in glob.glob(os.path.join(out, "traffic_*.jsonl")):
        os.remove(old_log)

    if args.attacks == ["none"]:
        specs = []
    else:
        only = None if args.attacks == ["all"] else set(args.attacks)
        specs = orchestrator.load_specs(os.path.join(ATTACKS, "scenarios"), only)
    if specs and args.duration < WARMUP_S + END_MARGIN_S + MIN_GAP_S:
        sys.exit(f"Sesja z atakami musi trwać co najmniej {WARMUP_S + END_MARGIN_S + MIN_GAP_S} s "
                 f"(inaczej żaden atak nie zmieści się przed końcowym marginesem).")

    setLogLevel("warning")
    topology.cleanup()
    topology.ensure_ovs()
    net = topology.build()
    handles, cap, workers, planned, broken = [], None, {}, 0, False
    try:
        net.start()
        topology.disable_offload(net)
        handles = services.start_services(net)

        r0 = net.get("r0")
        # tcpdump startuje przed ruchem, a sekunda przerwy daje mu czas na otwarcie interfejsów
        cap = r0.popen(topology.capture_cmd(pcap), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)

        session_start = time.time()
        deadline = session_start + args.duration
        # ruch normalny w tle na całą sesję
        workers = generator.start_workers(net, out, args.seed, args.duration, args.start_hour)
        time.sleep(WARMUP_S)  # trochę czystego ruchu normalnego, zanim ruszą ataki
        # ataki rozłożone na całą sesję (nie wszystkie na początku); zainfekowany host wstrzymuje
        # swój ruch normalny na czas ataku, żeby jego legalne połączenia do celu (np. przeglądanie
        # serwera web = cel skanu) nie dostały etykiety ataku. Zewnętrzny atakujący (atk) nie ma
        # generatora, więc go to nie dotyczy. Wstrzymanie to świadomy kompromis (czyste etykiety
        # kosztem realizmu), opisany w pracy.
        if specs:
            rng = random.Random(args.seed)
            schedule = plan_attack_schedule(specs, args.duration, rng)
            planned = len(schedule)
            internal_index = 0
            occurrence_number = 1
            quiet_until = 0.0  # najwcześniejsza chwila startu kolejnego ataku (cisza po poprzednim)
            for start_offset, spec in schedule:
                # czekam do zaplanowanej chwili, ale nie krócej niż cisza po poprzednim ataku
                # i nie dłużej niż do końca sesji
                wait = max(session_start + start_offset, quiet_until) - time.time()
                if wait > 0:
                    time.sleep(min(wait, max(0.0, deadline - time.time())))
                if time.time() >= deadline - END_MARGIN_S:
                    break  # pod koniec sesji nie zaczynam nowych ataków
                attacker = pick_attacker(spec, internal_index, args.attacker)
                if not args.attacker and spec["attacker"] != "atk":
                    internal_index += 1  # tylko ataki wewnętrzne przesuwają rotację o3 -> d2 -> o5
                occurrence = vary_params(spec, rng)
                occurrence["name"] = f"{spec['name']}_{occurrence_number:02d}"  # osobny log i rekord GT
                occurrence_number += 1
                proc = workers.get(attacker)  # host -> proces generatora
                if proc:
                    try:
                        signal_worker(proc, signal.SIGSTOP)  # wstrzymanie ruchu normalnego atakującego
                    except Exception:
                        proc = None
                # run_attack czeka, aż atak się skończy, i dopisuje rekord do ground_truth.jsonl
                orchestrator.run_attack(net, occurrence, out, attacker)
                quiet_until = time.time() + QUIET_AFTER_ATTACK_S
                if proc:
                    try:
                        signal_worker(proc, signal.SIGCONT)
                    except Exception:
                        pass
        # dograj ruch normalny do końca sesji
        remaining = deadline - time.time()
        if remaining > 0:
            time.sleep(remaining)

        # SIGTERM do całej grupy procesów workera: kończy też curl, ssh i scp w trakcie,
        # a worker zapisuje worker_stop. Worker, który nie skończy w 5 s, dostaje SIGKILL.
        for w in workers.values():
            signal_worker(w, signal.SIGTERM)
        for w in workers.values():
            try:
                w.wait(timeout=5)  # workery muszą się zakończyć, zanim zatrzymamy nagrywanie i sieć
            except subprocess.TimeoutExpired:
                signal_worker(w, signal.SIGKILL)
                w.wait(timeout=5)
        time.sleep(1)
        cap.terminate()
        cap.wait(timeout=10)

        # krótkie podsumowanie
        pkts, max_gap, went_back = capture_summary(pcap)
        n_gt = 0
        if os.path.exists(gt):
            with open(gt) as f:
                n_gt = sum(1 for _ in f)
        print(f"Sesja: {args.duration} s, pakiety w capture: {pkts}, ataki: {n_gt} z {planned} zaplanowanych")
        print(f"  największa przerwa między pakietami: {max_gap:.1f} s")
        if max_gap > MAX_CAPTURE_GAP_S or went_back:
            broken = True
            print(f"  UWAGA: przerwa {max_gap:.0f} s albo cofnięcie czasu w nagraniu - maszyna WSL stała "
                  f"(uśpienie, skok zegara). Sesję trzeba nagrać ponownie.")
        print(f"  pcap: {pcap}")
        print(f"  ground truth: {gt}")
    finally:
        for w in workers.values():
            try:
                signal_worker(w, signal.SIGCONT)  # odblokuj ewentualnie wstrzymany worker przed zakończeniem
            except Exception:
                pass
            try:
                w.terminate()
            except Exception:
                pass
        if cap:
            try:
                cap.terminate()
            except Exception:
                pass
        services.stop_services(handles)
        net.stop()
        topology.cleanup()
    if broken:
        sys.exit(2)


if __name__ == "__main__":
    main()
