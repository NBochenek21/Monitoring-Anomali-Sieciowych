#!/usr/bin/env python3
"""Minimalny serwer HTTP do generowania ruchu w izolowanym laboratorium Mininet.

Zainfekowany host (bot) co jakiś czas melduje się u serwera atakującego (C2 command and control)
- pyta się o polecenia i czasami też odsyła "wykradzione" dane (eksfiltracja). Takie pojedyncze połączenie
wygląda jak zwykłe wejście na stronę. Atak zdradza dopiero rytm - połączenia do tego samego zewnętrznego
adresu co jakiś czas (ok. 45 s) przez kilka minut.

U mnie serwer C2 to host c2 (203.0.113.12) w segmencie external, a klientem (bot) jest stacja z rotacji
o3 -> d2 -> o5. Parametry klienta (liczba meldunków, odstęp, jitter, eksfiltracja) są w
attacks/scenarios/Z1_c2_beaconing.yaml, a sam klient w attacks/tools/beacon_client.py.

To atak niewidziany w treningu - model nie zna go ze zbiorów CIC ani GeNIS - sprawdzamy, czy wykryje anomalię.

    python3 beacon_endpoint.py --bind 203.0.113.12 --port 80 --log /tmp/lab/c2/requests.log
"""
import argparse
import datetime
import http.server # serwer HTTP wbudowany w Pythona
import os
import threading

#Serwer przyjmuje klase handlera i sam tworzy jej obiekty, wiec nie da się mu przekazac parametrów w zwykły sposób
#Dlatego klasa jest zdefiniowana w środku funckji i widzi wtedy zmienne log_path, upload_dir i lock z otaczającej
#go funckji a make_handler zwraca gotowa klase z wbudowanymi ustawieniami
def make_handler(log_path, upload_dir):
    lock = threading.Lock() #blokada wątku aby nie zapisywać do pliku logu w tym samym czasie z np. dwóch wątków 

    # obsługa jednego żądania HTTP: serwer tworzy nowy obiekt tej klasy dla każdego połączenia
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "lab-telemetry/1.0" #początek nagłówka Server: w odpowiedzi (http.server dokleja wersję Pythona)

        #zapisuje informacje o żądaniu do pliku logu - czas, adres bota, rodzaj żądania (checkin/upload)
        #ścieżka i liczba bajtów
        def _record(self, kind, nbytes):
            line = (f"{datetime.datetime.now().isoformat()}\t{self.client_address[0]}\t"
                    f"{kind}\t{self.path}\t{nbytes}\n")
            with lock, open(log_path, "a") as f:
                f.write(line)


        #zapis żądania GET (meldunek bota) do logu i odsyła prostą odpowiedź 200 OK z treścią ok
        #mówi klientowi ile bajtów ma przeczytać
        def do_GET(self):
            self._record("checkin", 0)
            body = b"OK\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


        #z nagłowka Content-Length odczytuje ile bajtów przyslal klient
        #self.rfile.read(length) odczytuje dokładnie tyle - prawdziwy rozmiar przepływu
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(length) if length else b""
            if upload_dir and data:
                name = datetime.datetime.now().strftime("%Y%m%d_%H%M%S_%f") + ".bin"
                with open(os.path.join(upload_dir, name), "wb") as f:
                    f.write(data)
            self._record("upload", len(data))
            body = b"OK\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        #domyślnie http.server wypisuje kazde zadanie na ekran - napisana metoda nic nie robi - sam sobie loguje
        def log_message(self, *args):
            return  # log zapisujemy we własnym formacie w _record

    return Handler


# argumenty, katalogi na log i uploady, potem serwer wielowątkowy (każde połączenie w osobnym wątku)
# działa, aż services.py zatrzyma proces
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--log", required=True)
    parser.add_argument("--upload-dir", default=None)
    args = parser.parse_args()

    os.makedirs(os.path.dirname(os.path.abspath(args.log)), exist_ok=True)
    if args.upload_dir:
        os.makedirs(args.upload_dir, exist_ok=True)
    httpd = http.server.ThreadingHTTPServer((args.bind, args.port), make_handler(args.log, args.upload_dir))
    httpd.serve_forever()


if __name__ == "__main__":
    main()
