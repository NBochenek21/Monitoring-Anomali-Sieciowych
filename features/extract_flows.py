#!/usr/bin/env python3
"""Ekstrakcja przepływów NFStreamem: pcap -> tabela przepływów (parquet), bez etykiet.

To samo narzędzie i te same ustawienia dla CIC-IDS2017, GeNIS i Mininetu, żeby cechy były porównywalne.
Kroki: usunięcie pakietów o identycznych bajtach do 0,5 ms po sobie (editcap; w CIC duplikaty z nagrania,
w Mininecie powtórzone przez jądro RST) i ułożenie ich po czasie (reordercap), NFStream
(idle 60 s, active 120 s, tylko IPv4 TCP/UDP, bez DPI) i nasza wtyczka zamykania połączeń TCP.
Obok wyniku zapisuje .meta.json z wersjami narzędzi i parametrami.

    python3 features/extract_flows.py --pcap /root/sessions/M1/capture.pcap --out /root/sessions/M1/flows
"""
import argparse
import glob
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile

import nfstream
import pandas as pd
from nfstream import NFPlugin, NFStreamer

TCP = 6
PCAP_EXT = (".pcap", ".pcapng", ".cap")
#parametry takie same dla wszystkich danych; bez DPI (wynik L7 zależy od wersji nDPI).
IDLE_TIMEOUT = 60
ACTIVE_TIMEOUT = 120
BPF_FILTER = "ip and (tcp or udp)"
#okno deduplikacji pakietów editcap -w [s].
DEDUP_WINDOW = 0.0005
#kolumny bez wartości dla modelu, zdradzające środowisko (MAC, OUI) albo puste bez DPI (L7).
DROP_COLUMNS = ["src_mac", "src_oui", "dst_mac", "dst_oui", "vlan_id", "tunnel_id", "ip_version",
                "udps.tcp_fin_mask",
                "application_name", "application_category_name", "application_is_guessed",
                "application_confidence", "requested_server_name", "client_fingerprint",
                "server_fingerprint", "user_agent", "content_type"]


#wtyczka NFStream: zamyka przepływ TCP, gdy połączenie się skończy - po RST albo po FIN z obu stron
#i ostatnim ACK; bez niej kolejne połączenie z tymi samymi adresami i portami dokleiłoby się do starego
#on_init = pierwszy pakiet przepływu, on_update = każdy następny; expiration_id = -1 zamyka przepływ
class TcpTermination(NFPlugin):

    #pierwszy pakiet przepływu: zerujemy maskę FIN i sprawdzamy pakiet jak każdy kolejny
    def on_init(self, packet, flow):
        flow.udps.tcp_fin_mask = 0  #bit 0: FIN od źródła, bit 1: FIN od celu
        self._step(packet, flow)

    #każdy kolejny pakiet tego przepływu
    def on_update(self, packet, flow):
        self._step(packet, flow)

    #jeden pakiet TCP: RST kończy przepływ od razu, FIN zapisuję w masce (0 = od źródła, 1 = od celu),
    #a pusty ACK po FIN z obu stron domyka połączenie
    def _step(self, packet, flow):
        if packet.protocol != TCP:
            return
        if packet.rst:
            flow.expiration_id = -1
            return
        if packet.fin:
            flow.udps.tcp_fin_mask |= 1 << packet.direction
            return
        if flow.udps.tcp_fin_mask == 3 and packet.ack and packet.payload_size == 0:
            flow.expiration_id = -1  #końcowy ACK po FIN z obu stron


#wtyczka NFStream: bajty danych (bez nagłówków) w każdym kierunku przepływu
#to nie jest cecha modelu - służy tylko do klasy "attempted" (atak, w którym atakujący nie wysłał danych)
class PayloadBytes(NFPlugin):

    #pierwszy pakiet: liczniki od zera, potem liczymy go jak każdy następny
    def on_init(self, packet, flow):
        flow.udps.src2dst_payload_bytes = 0
        flow.udps.dst2src_payload_bytes = 0
        self.on_update(packet, flow)

    #dodaje rozmiar danych pakietu do licznika jego kierunku
    def on_update(self, packet, flow):
        if packet.direction == 0:
            flow.udps.src2dst_payload_bytes += packet.payload_size
        else:
            flow.udps.dst2src_payload_bytes += packet.payload_size


#pierwsza linia z wersją (editcap ma -V, reordercap tylko -h).
def tool_version(cmd):
    for flag in ("-V", "-h"):
        try:
            res = subprocess.run([cmd, flag], capture_output=True, text=True)
        except FileNotFoundError:
            sys.exit(f"Brak {cmd} (pakiet wireshark-common).")
        lines = (res.stdout + res.stderr).splitlines()
        if lines and "Wireshark" in lines[0]:
            return lines[0].strip()
    return "?"


#editcap (pcap + deduplikacja) i reordercap. Zwraca (ścieżka, statystyka).
def prepare(src, tmpdir):
    deduped = os.path.join(tmpdir, "dedup.pcap")
    cmd = ["editcap", "-F", "pcap", "-w", str(DEDUP_WINDOW)]
    res = subprocess.run(cmd + [src, deduped], capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"editcap: {res.stderr.strip()}")
    stats = {"editcap": " ".join(res.stderr.split())[:300]}
    #editcap pisze na stderr np. "1000 packets seen, 3 packets skipped" - skipped to usunięte pakiety
    #o identycznych bajtach; w Mininecie (-Q in, bez kopii w nagraniu) to powtórzone przez jądro RST
    #(w M1 z 13.11 wszystkie 756 to RST atk -> web:80; w sesjach z 20-21.11: 416-581 na sesję)
    m = re.search(r"(\d+) packets? seen, (\d+) packets? skipped", res.stderr)
    if m:
        stats["packets_seen"], stats["duplicates_removed"] = int(m.group(1)), int(m.group(2))
    ordered = os.path.join(tmpdir, "ordered.pcap")
    res = subprocess.run(["reordercap", deduped, ordered], capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"reordercap: {res.stderr.strip()}")
    stats["reordercap"] = " ".join((res.stdout + res.stderr).split())[:300]
    os.remove(deduped)
    return ordered, stats


#właściwa ekstrakcja: NFStream czyta pcap i zwraca tabelę - jeden wiersz to jeden przepływ, ok. 70 statystyk
#bez DPI (n_dissections=0), ze statystykami rozmiarów, odstępów i flag, z naszymi dwiema wtyczkami
#tcp_plugin zmienia się tylko w teście (None = bez wtyczki, same timeouty)
def extract(pcap, tcp_plugin="default"):
    if tcp_plugin == "default":
        tcp_plugin = TcpTermination()
    plugins = ([tcp_plugin] if tcp_plugin is not None else []) + [PayloadBytes()]
    streamer = NFStreamer(source=pcap, decode_tunnels=False, bpf_filter=BPF_FILTER,
                          idle_timeout=IDLE_TIMEOUT, active_timeout=ACTIVE_TIMEOUT,
                          n_dissections=0, statistical_analysis=True, udps=plugins)
    df = streamer.to_pandas()
    if df is None:  #NFStream zwraca None, gdy nie powstał żaden przepływ
        return pd.DataFrame()
    df = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns])
    #kolumny z wtyczek mają przedrostek udps. - zostawiamy krótkie nazwy
    df = df.rename(columns={"udps.src2dst_payload_bytes": "src2dst_payload_bytes",
                            "udps.dst2src_payload_bytes": "dst2src_payload_bytes"})
    #sortowanie po starcie przepływu; id NFStreama jako drugi klucz, żeby przy tym samym czasie startu
    #kolejność była zawsze ta sama
    df = df.sort_values(["bidirectional_first_seen_ms", "id"], kind="stable").reset_index(drop=True)
    df["id"] = range(len(df))  #nowe id = pozycja po sortowaniu
    return df


#numery typów łącza z nagłówka pcap -> czytelne nazwy (do ostrzeżenia, gdy wyjdzie 0 przepływów)
LINKTYPE_NAMES = {1: "Ethernet", 113: "Linux cooked v1 (SLL)", 276: "Linux cooked v2 (SLL2)", 101: "raw IP"}


#typ łącza z nagłówka pliku pcap (np. Ethernet, SLL)
#nagłówek ma 24 bajty: pierwsze 4 mówią o kolejności bajtów, a bajty 20-23 to typ łącza
def linktype(pcap):
    with open(pcap, "rb") as f:
        hdr = f.read(24)
    if len(hdr) < 24:
        return None
    order = "<" if hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    return struct.unpack(order + "I", hdr[20:24])[0] & 0x0FFFFFFF


#lista plików: wszystkie pcap z katalogu (z podkatalogami) albo jeden podany plik
#dwa pliki o tej samej nazwie w różnych podkatalogach nadpisałyby wynik, więc wtedy błąd
def find_pcaps(path):
    if os.path.isdir(path):
        all_files = glob.glob(os.path.join(path, "**", "*"), recursive=True)
        files = sorted(file for file in all_files if file.lower().endswith(PCAP_EXT))
        names = [os.path.splitext(os.path.basename(file))[0] for file in files]
        clashes = sorted({name for name in names if names.count(name) > 1})
        if clashes:
            sys.exit(f"Pliki o tej samej nazwie w różnych podkatalogach (wynik by się nadpisał): {clashes}")
        return files
    return [path]


#dla każdego pliku: usunięcie duplikatów i ułożenie pakietów, ekstrakcja, zapis .parquet
#oraz .meta.json z wersjami narzędzi i parametrami, żeby wynik dało się odtworzyć
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--pcap", required=True, help="plik pcap/pcapng albo katalog")
    parser.add_argument("--out", required=True, help="katalog wyjściowy")
    parser.add_argument("--tmp", default=tempfile.gettempdir(), help="katalog na pliki pośrednie")
    args = parser.parse_args()

    files = find_pcaps(args.pcap)
    if not files:
        sys.exit(f"Brak plików PCAP w {args.pcap}")
    os.makedirs(args.out, exist_ok=True)
    versions = {"nfstream": nfstream.__version__, "editcap": tool_version("editcap"),
                "reordercap": tool_version("reordercap")}
    params = {"tcp_expiry": "rst_or_fin_both_sides_then_ack", "idle": IDLE_TIMEOUT, "active": ACTIVE_TIMEOUT,
              "bpf": BPF_FILTER, "dpi": 0, "dedup_window": DEDUP_WINDOW}

    for f in files:
        name = os.path.splitext(os.path.basename(f))[0]
        tmpdir = tempfile.mkdtemp(prefix="flows_", dir=args.tmp)
        try:
            ready, stats = prepare(f, tmpdir)
            lt = linktype(ready)
            stats["linktype"] = LINKTYPE_NAMES.get(lt, lt)
            df = extract(ready)
            if df.empty:
                print(f"UWAGA {os.path.basename(f)}: 0 przepływów, typ łącza: {stats['linktype']}. "
                      "NFStream czyta Ethernet, SLL v1 i raw IP; SLL2 nie (nagrywaj z -y LINUX_SLL).")
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)  #pliki pośrednie usuwamy także po błędzie
        out = os.path.join(args.out, f"{name}.parquet")
        df.to_parquet(out, index=False)
        #jak skończyły się przepływy (-1 = nasza wtyczka, 0 = bezczynność, 1 = za długi) - kontrola wtyczki
        exp = df["expiration_id"].value_counts().items() if not df.empty else []
        meta = {"source": os.path.abspath(f), "source_bytes": os.path.getsize(f), "flows": len(df),
                "expiration_id_counts": {str(k): int(v) for k, v in exp},
                "versions": versions, "params": params, "prepare": stats}
        with open(os.path.join(args.out, f"{name}.meta.json"), "w") as g:
            json.dump(meta, g, indent=2, ensure_ascii=False)
        dup = stats.get("duplicates_removed", "?")
        print(f"{os.path.basename(f)}: {len(df)} przepływów (duplikaty usunięte: {dup}) -> {out}")


if __name__ == "__main__":
    main()
