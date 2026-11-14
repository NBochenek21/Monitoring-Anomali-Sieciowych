#!/usr/bin/env python3
#shebang pozwala uruchomić skrypt bezpośrednio w linuksie

"""Buduje i testuje topologię sieci w Mininecie.

Uruchamianie w WSL2 jako root:
    python3 env/topology.py
    python3 env/topology.py --cli
"""
import argparse #argumenty wiersza polecen
import json #wypisywanie wyników testów
import os #operacja na systemie plików
import re #regexy do parsowania
import subprocess #wywoływanie komend systemowych 
import sys #sys.exit
import time #czekanie na start tcpdump w teście nagrywania

from mininet.net import Mininet #obiekt calej sieci
from mininet.cli import CLI #konsola
from mininet.link import Link, TCLink #łącza zwykłe i z emulacją opóznień (netem)
from mininet.log import setLogLevel #ilość wypisywanych logów
from mininet.node import Host, OVSBridge #bazowy host i switch Open vSwitch



#cały kształt topologii sieci jest opisany jako słowniki, inne pliki importuja
#i biorą stąd adresy.

#klucz  : (wartosci)
#segment: (switch, int routera, podsieć, adres bramy)
SEGMENTS = {
    "biuro": ("s1", "r0-eth0", "10.0.1.0/24", "10.0.1.1"),
    "deweloperzy": ("s2", "r0-eth1", "10.0.2.0/24", "10.0.2.1"),
    "administratorzy": ("s3", "r0-eth2", "10.0.3.0/24", "10.0.3.1"),
    "serwery": ("s4", "r0-eth3", "10.0.10.0/24", "10.0.10.1"),
    "external": ("s5", "r0-eth4", "203.0.113.0/24", "203.0.113.1"),
}

#klucz: (wartosci -krotka)
#host : (segment, adres IP)
HOSTS = {
    "o1": ("biuro", "10.0.1.10"), #office
    "o2": ("biuro", "10.0.1.11"),
    "o3": ("biuro", "10.0.1.12"),
    "o4": ("biuro", "10.0.1.13"),
    "o5": ("biuro", "10.0.1.14"),
    "o6": ("biuro", "10.0.1.15"),
    "q1": ("biuro", "10.0.1.16"), #quiet
    "q2": ("biuro", "10.0.1.17"),

    "d1": ("deweloperzy", "10.0.2.10"), #devs
    "d2": ("deweloperzy", "10.0.2.11"),
    "d3": ("deweloperzy", "10.0.2.12"),

    "a1": ("administratorzy", "10.0.3.10"), #admin
    "a2": ("administratorzy", "10.0.3.11"),

    "web": ("serwery", "10.0.10.10"), #servers
    "dns": ("serwery", "10.0.10.11"),
    "ssh": ("serwery", "10.0.10.12"),
    "files": ("serwery", "10.0.10.13"),
    "mail": ("serwery", "10.0.10.14"),

    "xweb": ("external", "203.0.113.10"), #external
    "xdns": ("external", "203.0.113.11"),
    "c2": ("external", "203.0.113.12"),
    "atk": ("external", "203.0.113.13"),
}

#polecenia sysctl (IPv6) i nazwy funkcji ethtool (offloading) używane do ich wyłączenia

#IPv6 W TEJ SIECI JEST WYŁĄCZONE W DWÓCH MIEJSCACH:
# 1) w WSL na stałe: /etc/sysctl.d/90-lab-ipv6.conf (tworzy go env/setup/install_wsl_packages.sh),
#    więc porty switchy, które powstają w głównej przestrzeni nazw WSL, od razu nie mają IPv6;
#    build() sprawdza to ustawienie i kończy program z komunikatem, jeśli go brakuje,
# 2) w każdym hoście (LabHost niżej): host ma własną przestrzeń nazw, a jądro nie przenosi
#    do niej ustawienia z WSL (sprawdzone 29.10.2026), więc host wyłącza IPv6 sam.
#Test ipv6_off w run_checks potwierdza, że na r0 nie ma żadnego pakietu IPv6.

#wyłączenie - wszytkich int, domyślny dla nowych i loopback
#robimy to bo mininet domyślnie włącza IPv6 - niepotrzebny szum przez ogłoszenia sasiedztwa itp
IPV6_OFF = (
    "sysctl -qw net.ipv6.conf.all.disable_ipv6=1 "
    "net.ipv6.conf.default.disable_ipv6=1 "
    "net.ipv6.conf.lo.disable_ipv6=1"
)
#wyłączenie offloadingu - nie chcemy pakietów większych niż MTU - zepsułoby cechy rozmiar pakietu
OFFLOADS = ("tcp-segmentation-offload", "generic-segmentation-offload", "generic-receive-offload")
#ustawienie WSL dla nowo powstających interfejsów - musi być 1 (sprawdza je build())
ROOT_V6_DEFAULT = "/proc/sys/net/ipv6/conf/default/disable_ipv6"

#dziedziczymy po klasie host Minineta - host bez IPv6
class LabHost(Host):

    # zwykły host Minineta, tylko od razu po utworzeniu wyłącza w sobie IPv6
    def __init__(self, name, **params):
        super().__init__(name, **params) #tworzenie hosta 
        self.cmd(IPV6_OFF) #wyłączenie IPv6 przy starcie hosta

#dziedziczymy po LabHost - też nie chce IPv6 na routerze
# Router r0: host z włączonym przekazywaniem pakietów IPv4.
class LinuxRouter(LabHost):

    # Mininet woła config() przy starcie sieci; po zwykłej konfiguracji włączamy routowanie
    def config(self, **params):
        result = super().config(**params)
        self.cmd("sysctl -qw net.ipv4.ip_forward=1") # włączenie przekazywania pakietów IPv4
        return result

#opóźnienia łączy w ms: dostępowe (host-switch) i WAN (r0-s5, "Internet")
#bez jittera: netem z jitterem przestawia kolejność pakietów i tworzy sztuczne retransmisje TCP
LAN_DELAY_MS = 1.0
WAN_DELAY_MS = 20.0


# Zbuduj sieć, ale jej jeszcze nie uruchamiaj.
def build():
    #porty switchy dostaną IPv6, jeśli w WSL brakuje ustawienia z install_wsl_packages.sh
    with open(ROOT_V6_DEFAULT) as f:
        if f.read().strip() != "1":
            sys.exit("IPv6 w WSL nie jest wyłączone: uruchom env/setup/install_wsl_packages.sh "
                     "(tworzy /etc/sysctl.d/90-lab-ipv6.conf).")

    #tworzymy siec bez kontrolera SDN, switche OVS w trybie samouczącym się - klasyczy tryb, hosty bez IPv6, 
    #poukładane adresy MAC - każde uruchomienie wyglada tak samo.
    net = Mininet(controller=None, switch=OVSBridge, host=LabHost, link=Link, autoSetMacs=True)
    first_gateway = SEGMENTS["biuro"][3]
    #dostaje IP bramy segmentu biuro jako pierwszy adres
    #adres dla pierwszego interfejsu, bo tak działa Mininet - nie chcemy losowego
    r0 = net.addHost("r0", cls=LinuxRouter, ip=f"{first_gateway}/24")
    


    switches = {} # pusty dict na switche
    #pętla po segmentach, dla każdego dodaje switch, wylicza prefiks, wybiera łącze, tworzy lącze switch router
    for segment, (switch_name, router_interface, subnet, gateway) in SEGMENTS.items():
        switches[segment] = net.addSwitch(switch_name) # dodanie switcha
        prefix = subnet.split("/")[1] #wyciągamy prefiks
        link_options = {} #dict z opcjami łącza
        if segment == "external": #dla external dodajemy opóźnienie WAN (łącze z netem)
            link_options = {"cls": TCLink, "delay": f"{WAN_DELAY_MS}ms"}

        net.addLink(
            switches[segment], #jaki switch
            r0, #do routera
            intfName2=router_interface, #np. r0-eth0, r0-eth1 itp
            params2={"ip": f"{gateway}/{prefix}"}, #ten int ma adres bramy segmentu
            **link_options,
        )

    #pętla po hostach - kazdy host dostaje swój adres IP/prefix i domyślną bramę
    for name, (segment, ip) in HOSTS.items():
        _, _, subnet, gateway = SEGMENTS[segment] #przipisanie zmiennych 
        prefix = subnet.split("/")[1] #wyciągamy prefiks z podsieci
        host = net.addHost(name, ip=f"{ip}/{prefix}", defaultRoute=f"via {gateway}") #dodanie hosta

        #dla każdego hosta dodajemy łącze z odpowiednim switchem (z opóźnieniem LAN)
        net.addLink(host, switches[segment], cls=TCLink, delay=f"{LAN_DELAY_MS}ms") #host zawsze ma opóznienie LAN
    return net

#generator(yield) - przechodzi po wszystkich interfejsach wszystkich hostow i switchy pomijając loopback
#dzięki temu dwie funckje (offloading, test offloadingu) nie powtarzają tej samej pętli
def lab_interfaces(net):
    for node in net.hosts + net.switches:
        for intf in node.intfList():
            if intf.name != "lo":
                yield node, intf.name #oddaje wynik po jednym na żądanie

#wyłączenie offloadingu na wszystkich interfejsach węzłów sieci
def disable_offload(net):
    for node, name in lab_interfaces(net):
        node.cmd(f"ethtool -K {name} tso off gso off gro off 2>/dev/null")

#próbuje wystartować usługę open vswitch - a potem ovs-vsctl show sprawdza czy naprawde dziala
#jesli nie to kończy program błędem
def ensure_ovs():
    subprocess.run(["systemctl", "start", "openvswitch-switch"], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, check=False)
    if subprocess.run(["ovs-vsctl", "show"], stdout=subprocess.DEVNULL,
                      stderr=subprocess.DEVNULL).returncode != 0:
        sys.exit("Open vSwitch nie działa (ovs-vsctl show).")

#usuwa resztki wirtualnych interfejsów po poprzednich uruchomieniach (mogł być przerwany przebieg np)
def cleanup():
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)

#Otwiera interaktywną konsolę minineta, na jej czas podnosi poziom logów z warning na output
#po to żeby było widac wyniki poleceń w konsoli a potem wraca do warning
def run_cli(net):
    setLogLevel("output")
    try:
        CLI(net)
    finally:
        setLogLevel("warning")

# tcpdump z Ubuntu (pakiet tcpdump, 4.99.1), podany ścieżką. Instalacja nProbe dołożyła pakiet pfring
# z własnym tcpdump 4.99.4 w /usr/local/bin, który w PATH roota wygrywał z /usr/bin; sesje M0-M6
# z 4-5.11.2026 nagrał najpewniej ten drugi (ta sama libpcap 1.10.1 i ten sam format pliku).
# Ścieżka usuwa tę zależność od PATH: nagrywa zawsze ta sama wersja co po świeżej instalacji.
TCPDUMP = "/usr/bin/tcpdump"


#zwraca gotową listę argumentów tcpdump do nagrywania pakietów na r0 (wspólne dla sesji i testów)
# -i any -Q in: każdy pakiet routowany między segmentami jest łapany raz, na wejściu do r0.
# -y LINUX_SLL: nagłówek Linux cooked v1 zamiast domyślnego v2 (SLL2), bo NFStream czyta tylko v1.
# Nagrywa tylko ruch przechodzący przez r0 (między segmentami); ruch wewnątrz jednego segmentu,
# np. web <-> files w serwerowni, nie trafia do nagrania.
def capture_cmd(pcap):
    return [TCPDUMP, "-i", "any", "-y", "LINUX_SLL", "-Q", "in", "-s", "0", "-U", "-w", pcap]

#średnie opóźnienie RTT między hostem a adresem docelowym, w ms - używane tylko w testach
def avg_rtt(src, dst_ip, count=5):
    out = src.cmd(f"ping -c {count} -i 0.2 {dst_ip}")
    m = re.search(r"= [\d.]+/([\d.]+)/", out)
    return float(m.group(1)) if m else None

#automatyczny test sieci
def run_checks(net):
    results, checks = {}, {}

    #najpierw startuje tcpdump łapiący tylko IPv6 potem każdy pinguje każdego (pingall)
    #potem zatrzymuje nagrywanie, gdy strata pingall = 0 to przekazywanie pakietów dziala
    r0 = net.get("r0") #zwraca obiekt r0 z sieci
    pcap = "/tmp/topology_ipv6.pcap"
    cap = r0.popen([TCPDUMP, "-i", "any", "-nn", "-U", "-w", pcap, "ip6"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) #nie zaśmiecam ekranu logami
    results["pingall_loss_pct"] = net.pingAll(timeout="1")
    cap.terminate()#zatrzymanie tcpdump
    cap.wait(timeout=10) #czekam az zamknie sie plik
    out = subprocess.run([TCPDUMP, "-r", pcap, "-nn"], capture_output=True, text=True).stdout
    results["ipv6_packets_on_r0"] = len([line for line in out.splitlines() if line.strip()])  #niepuste linie
    checks["pingall"] = results["pingall_loss_pct"] == 0 

    #ipv6_off zlicza linie w tym IPv6 nagraniu - musi być zero pakietów; samo nagranie to słaby dowód
    #(ogłoszenia IPv6 lecą przy podnoszeniu interfejsów, zanim tcpdump ruszy), więc dodatkowo
    #każdy host musi mieć disable_ipv6 = 1 we własnej przestrzeni nazw
    results["ipv6_on_hosts"] = [host.name for host in net.hosts
                                if host.cmd("cat /proc/sys/net/ipv6/conf/all/disable_ipv6").strip() != "1"]
    checks["ipv6_off"] = results["ipv6_packets_on_r0"] == 0 and not results["ipv6_on_hosts"]

   
    results["offload_on"] = [f"{name}:{k}" for node, name in lab_interfaces(net)
                         for k in OFFLOADS if re.search(rf"^{k}: on", node.cmd(f"ethtool -k {name}"), re.M)]
    #offload_off - czyta ethtool -k i szuka : on  - lista musi być pusta
    checks["offload_off"] = not results["offload_on"]

    #rtt_lan / rtt_wan - mierzy RTT z o1 do serwera(LAN) i o1 do xweb(WAN) i porównuje z oczekiwanym. 
    o1 = net.get("o1")
    results["rtt_lan_ms"] = avg_rtt(o1, HOSTS["web"][1])
    results["rtt_wan_ms"] = avg_rtt(o1, HOSTS["xweb"][1])
    results["rtt_lan_expected_ms"] = 4 * LAN_DELAY_MS # dwa łącza tam i z powrotem,
    results["rtt_wan_expected_ms"] = 2 * (2 * LAN_DELAY_MS + WAN_DELAY_MS)

    # dopuszczamy odchylenie 1ms lub 30%  oczekiwanej
    def close(measured, expected):
        return measured is not None and abs(measured - expected) <= max(1.0, 0.3 * expected)

    checks["rtt_lan"] = close(results["rtt_lan_ms"], results["rtt_lan_expected_ms"])
    checks["rtt_wan"] = close(results["rtt_wan_ms"], results["rtt_wan_expected_ms"])

    #capture_once - nagrywamy tym samym poleceniem co sesje (capture_cmd) i pingujemy o1 -> web (przez r0).
    #-Q in: każdy pakiet zapisany raz, czyli 10 żądań + 10 odpowiedzi (bez -Q in byłoby 40).
    #Przed "superpakietami" większymi niż MTU chroni test offload_off wyżej.
    pcap = "/tmp/topology_capture.pcap"
    if os.path.exists(pcap):
        os.remove(pcap)
    cap = r0.popen(capture_cmd(pcap), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100): #czekamy, aż tcpdump zacznie słuchać (zapisze nagłówek pliku)
        if os.path.exists(pcap) and os.path.getsize(pcap) > 0:
            break
        time.sleep(0.1)
    o1.cmd(f"ping -c 10 -i 0.2 {HOSTS['web'][1]}")
    time.sleep(1)
    cap.terminate()
    cap.wait(timeout=10)
    dump = subprocess.run([TCPDUMP, "-r", pcap, "-nn", "icmp"], capture_output=True, text=True).stdout
    results["capture_icmp_packets"] = len([line for line in dump.splitlines() if line.strip()])
    checks["capture_once"] = results["capture_icmp_packets"] == 20
    return results, checks #zwracamy oba dicty

#parsuje argumenty (--cli), sprawdza roota, ucisza logi, sprzta po poprzednich
#przebiegach, upewnia się co do OVS
def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cli", action="store_true", help="po testach otwórz konsolę Mininetu") #odczyt czy podano cli
    args = parser.parse_args()

    if os.geteuid() != 0: #sprawdzamy czy dziala jako root
        sys.exit("Uruchom jako root.")
    setLogLevel("warning") # mininet wypisuje tylko ostrzeżenia
    cleanup() #sprząta resztki
    ensure_ovs() # sprawdza open vswitch


    #IPv6 na portach switchy wyłącza ustawienie WSL (sprawdza je build()), na hostach LabHost
    net = build()
    ok = False
    try:
        net.start()
        disable_offload(net)
        results, checks = run_checks(net)
        results["checks"] = checks
        print(json.dumps(results, indent=2, ensure_ascii=False))
        for name, passed in checks.items():
            print(f"{'OK  ' if passed else 'BŁĄD'} {name}") #wynik testów
        ok = all(checks.values()) #program konczy sie kodem 0
        if args.cli:
            run_cli(net)
    finally: # wykona sie zawsze
        net.stop()
        cleanup()
    sys.exit(0 if ok else 1)

#odpala main() tylko jeśli uruchomione ten plik bezpośrednio
if __name__ == "__main__":
    main()
