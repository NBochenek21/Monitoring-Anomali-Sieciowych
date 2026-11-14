#!/usr/bin/env python3
"""Test ekstrakcji (extract_flows.py) na syntetycznych PCAP-ach o znanym przebiegu.

Ruch testowy (klient 10.0.1.10:40000 -> serwer 10.0.10.10:80):
  A: SYN, SYN/ACK, ACK, dane, ACK, FIN/ACK (k), FIN/ACK (s), ACK (k)   -- 8 pakietów
     + duplikat pakietu z danymi po 0,1 ms (do usunięcia przez deduplikację)
  B: po 2 s ta sama piątka: SYN, SYN/ACK, ACK, RST (k)                  -- 4 pakiety
  U: zapytanie i odpowiedź DNS po UDP                                   -- 2 pakiety

Oczekiwane przepływy TCP: A (8) i B (4), bez resztek połączenia; deduplikacja usuwa 1 pakiet.
Ten sam plik jako SLL v1 daje to samo; jako SLL2 NFStream nie czyta nic (stąd -y LINUX_SLL).

Warianty porównawcze (opis w 7.1), na tym samym pliku Ethernet:
  - zamykanie na pierwszym FIN: A kończy się na FIN klienta (6 pakietów). FIN serwera otwiera
    resztkowy przepływ, który ten sam FIN od razu zamyka (1 pakiet), a końcowy ACK klienta otwiera
    nowy przepływ i dokleja się do połączenia B (1 + 4 pakiety): TCP [6, 1, 5];
  - same timeouty (bez wtyczki): B przychodzi 2 s po A, czyli przed idle 60 s, więc oba połączenia
    sklejają się w jeden przepływ: TCP [12].

    python3 features/test_extract_flows.py
"""
import json
import os
import struct
import subprocess
import sys
import tempfile

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
EXTRACT = os.path.join(HERE, "extract_flows.py")
sys.path.insert(0, HERE)
import extract_flows  # noqa: E402  (warianty zamykania TCP liczone w tym procesie)
from nfstream import NFPlugin  # noqa: E402
CLIENT, SERVER, DNS = "10.0.1.10", "10.0.10.10", "10.0.10.11"
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10
LINKTYPE = {"ether": 1, "sll": 113, "sll2": 276}


# Adres IP jako 4 bajty, np. "10.0.1.10" -> b"\x0a\x00\x01\x0a".
def ip_bytes(a):
    return bytes(int(part) for part in a.split("."))


# Suma kontrolna nagłówka IPv4 (RFC 791): suma słów 16-bitowych z przeniesieniem, potem negacja.
def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


# Pakiet IPv4: 20-bajtowy nagłówek (TTL 64, flaga DF) z poprawną sumą kontrolną + zawartość.
def ipv4(src, dst, proto, payload, ident):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, 0x4000, 64, proto, 0,
                      ip_bytes(src), ip_bytes(dst))
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


# Segment TCP: porty, numery sekwencyjne, flagi i dane (suma kontrolna 0 - NFStream jej nie sprawdza).
def tcp(sport, dport, seq, ack, flags, data=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + data


# Datagram UDP: porty, długość i dane (suma kontrolna 0 = brak, dozwolone w IPv4).
def udp(sport, dport, data):
    return struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data


# Pakiet IP opakowany w nagłówek warstwy łącza: Ethernet, Linux cooked v1 (SLL) albo v2 (SLL2).
def frame(kind, ip_pkt, outgoing):
    if kind == "ether":
        return b"\x02\0\0\0\0\x02" + b"\x02\0\0\0\0\x01" + b"\x08\x00" + ip_pkt
    if kind == "sll":  # pkttype, ARPHRD_ETHER, addr len, addr[8], protocol
        return struct.pack("!HHH8sH", 4 if outgoing else 0, 1, 6, b"\x02\0\0\0\0\x01\0\0", 0x0800) + ip_pkt
    # sll2: protocol, reserved, ifindex, ARPHRD_ETHER, pkttype, addr len, addr[8]
    return struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, 4 if outgoing else 0, 6, b"\x02\0\0\0\0\x01\0\0") + ip_pkt


# Lista (czas, pakiet IP, od_klienta).
def packets():
    t, c, s, ident = 1000.0, 40000, 80, [0]
    out = []

    # dopisuje pakiet dt sekund po starcie; ident = kolejny numer identyfikacyjny IP
    def add(dt, src, dst, l4, proto=6):
        ident[0] += 1
        out.append((t + dt, ipv4(src, dst, proto, l4, ident[0]), src == CLIENT))

    # A: pełne połączenie z zamknięciem FIN/FIN/ACK
    add(0.000, CLIENT, SERVER, tcp(c, s, 100, 0, SYN))
    add(0.010, SERVER, CLIENT, tcp(s, c, 500, 101, SYN | ACK))
    add(0.020, CLIENT, SERVER, tcp(c, s, 101, 501, ACK))
    add(0.030, CLIENT, SERVER, tcp(c, s, 101, 501, PSH | ACK, b"G" * 100))
    dup = out[-1]
    out.append((dup[0] + 0.0001, dup[1], dup[2]))  # duplikat (te same bajty)
    add(0.040, SERVER, CLIENT, tcp(s, c, 501, 201, ACK))
    add(0.050, CLIENT, SERVER, tcp(c, s, 201, 501, FIN | ACK))
    add(0.060, SERVER, CLIENT, tcp(s, c, 501, 202, FIN | ACK))
    add(0.070, CLIENT, SERVER, tcp(c, s, 202, 502, ACK))
    # B: ta sama piątka po 2 s, zakończona RST
    add(2.000, CLIENT, SERVER, tcp(c, s, 900, 0, SYN))
    add(2.010, SERVER, CLIENT, tcp(s, c, 700, 901, SYN | ACK))
    add(2.020, CLIENT, SERVER, tcp(c, s, 901, 701, ACK))
    add(2.030, CLIENT, SERVER, tcp(c, s, 901, 701, RST))
    # U: DNS po UDP
    add(3.000, CLIENT, DNS, udp(5353, 53, b"q" * 30), proto=17)
    add(3.010, DNS, CLIENT, udp(53, 5353, b"r" * 60), proto=17)
    return out


# Zapis pliku pcap: nagłówek pliku (wersja 2.4, typ łącza) i każdy pakiet z czasem i długością.
def write_pcap(path, kind):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, LINKTYPE[kind]))
        for ts, ip_pkt, outgoing in packets():
            data = frame(kind, ip_pkt, outgoing)
            sec = int(ts)
            usec = int(round((ts - sec) * 1e6))
            f.write(struct.pack("<IIII", sec, usec, len(data), len(data)) + data)


# Zwraca (przepływy, liczba usuniętych duplikatów).
def run(pcap, outdir):
    res = subprocess.run([sys.executable, EXTRACT, "--pcap", pcap, "--out", outdir],
                         capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"extract_flows.py zawiódł:\n{res.stdout}\n{res.stderr}")
    name = os.path.splitext(os.path.basename(pcap))[0]
    with open(os.path.join(outdir, f"{name}.meta.json")) as f:
        duplicates = json.load(f)["prepare"].get("duplicates_removed")
    return pd.read_parquet(os.path.join(outdir, f"{name}.parquet")), duplicates


# Wariant porównawczy: przepływ TCP kończy się na pierwszym FIN (albo RST), bez czekania na drugą stronę.
class FirstFinTermination(NFPlugin):
    def on_init(self, packet, flow):
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.protocol == 6 and (packet.fin or packet.rst):
            flow.expiration_id = -1


# Ekstrakcja w tym procesie z podaną regułą zamykania TCP (deduplikacja i kolejność jak w extract_flows).
def run_variant(pcap, tmpdir, tcp_plugin):
    os.makedirs(tmpdir, exist_ok=True)
    ready, _ = extract_flows.prepare(pcap, tmpdir)
    return extract_flows.extract(ready, tcp_plugin=tcp_plugin)


# Liczby pakietów w kolejnych przepływach TCP i ich adresy źródłowe (do porównania z oczekiwanymi).
def tcp_packets(df):
    t = df[df["protocol"] == 6].sort_values("bidirectional_first_seen_ms")
    return list(t["bidirectional_packets"]), list(t["src_ip"])


# Tworzy pliki testowe w trzech formatach, uruchamia na nich extract_flows.py i porównuje wynik
# z oczekiwanym: Ethernet i SLL v1 mają dać przepływy 8 i 4 pakiety + DNS, SLL2 ma dać 0.
# Na końcu dwa warianty porównawcze reguły zamykania TCP na pliku Ethernet.
def main():
    tmp = tempfile.mkdtemp(prefix="test_flows_")
    pcaps = {}
    for kind in LINKTYPE:
        pcaps[kind] = os.path.join(tmp, f"synthetic_{kind}.pcap")
        write_pcap(pcaps[kind], kind)

    cases = [
        ("Ethernet", pcaps["ether"], [8, 4], 3),
        ("SLL v1", pcaps["sll"], [8, 4], 3),
    ]
    ok = True
    for index, (name, pcap, want_tcp, want_total) in enumerate(cases):
        df, duplicates = run(pcap, os.path.join(tmp, f"out{index}"))
        got_tcp, srcs = tcp_packets(df)
        passed = got_tcp == want_tcp and len(df) == want_total and srcs[0] == CLIENT and duplicates == 1
        ok &= passed
        print(f"{'OK  ' if passed else 'BŁĄD'} {name}: TCP {got_tcp} (oczekiwane {want_tcp}), "
              f"razem {len(df)} (oczekiwane {want_total}), usunięte duplikaty {duplicates} (oczekiwane 1)")

    df, _ = run(pcaps["sll2"], os.path.join(tmp, "out_sll2"))
    sll2_ok = len(df) == 0
    ok &= sll2_ok
    print(f"{'OK  ' if sll2_ok else 'BŁĄD'} SLL2: {len(df)} przepływów (NFStream nie czyta SLL2, "
          "dlatego capture z -y LINUX_SLL)")

    # warianty porównawcze reguły zamykania TCP (dlaczego wtyczka TcpTermination)
    variants = [
        ("pierwszy FIN", FirstFinTermination(), [6, 1, 5],
         "resztkowy przepływ z FIN serwera, końcowy ACK doklejony do następnego połączenia"),
        ("same timeouty", None, [12], "oba połączenia sklejone w jeden przepływ"),
    ]
    for index, (name, plugin, want_tcp, meaning) in enumerate(variants):
        got_tcp, _ = tcp_packets(run_variant(pcaps["ether"], os.path.join(tmp, f"variant{index}"), plugin))
        passed = got_tcp == want_tcp
        ok &= passed
        print(f"{'OK  ' if passed else 'BŁĄD'} wariant {name}: TCP {got_tcp} (oczekiwane {want_tcp}: {meaning})")
    print("WYNIK:", "OK" if ok else "BŁĄD")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
