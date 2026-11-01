#!/usr/bin/env python3
"""Ekstrakcja przepływów NFStreamem: PCAP -> Parquet z cechami (bez etykiet).

Jedno narzędzie i jedna konfiguracja dla wszystkich danych (CIC-IDS2017, GeNIS, Mininet), żeby
cechy były porównywalne między domenami. Kroki dla każdego pliku:
  1. editcap: konwersja do pcap (także z pcapng) i usunięcie duplikatów pakietów w oknie czasu,
  2. reordercap: pakiety w kolejności znaczników czasu,
  3. NFStream z parametrami jak w NFS-2023 (Pekar i Jozsa 2024): idle 60 s, active 120 s,
     tylko IPv4 TCP/UDP, bez dekodowania tuneli, bez DPI, z analizą statystyczną,
  4. wtyczka TcpTermination: RST kończy przepływ od razu, a po FIN z obu stron przepływ kończy
     końcowy ACK. Tak domyka połączenie poprawiony CICFlowMeter (Engelen i in. 2021), bez
     resztkowych przepływów FIN/ACK po zamknięciu.

Wynik: <out>/<nazwa>.parquet (posortowany po starcie przepływu) i <out>/<nazwa>.meta.json
z wersjami narzędzi, parametrami i statystyką deduplikacji.

    python3 features/extract_flows.py --pcap data/pcap/M1/capture.pcap --out data/flows_raw/M1
    python3 features/extract_flows.py --pcap <katalog z pcap/pcapng> --out <katalog>
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
# Parametry jak w NFS-2023 (Pekar i Jozsa 2024, Computer Networks), takie same dla
# wszystkich danych; bez DPI (wynik L7 zależy od wersji nDPI).
IDLE_TIMEOUT = 60
ACTIVE_TIMEOUT = 120
BPF_FILTER = "ip and (tcp or udp)"
# Okno deduplikacji pakietów editcap -w [s], jak w CRiSIS-2022 (Lanvin i in.).
DEDUP_WINDOW = 0.0005
# Kolumny bez wartości dla modelu, zdradzające środowisko (MAC, OUI) albo puste bez DPI (L7).
DROP_COLUMNS = ["src_mac", "src_oui", "dst_mac", "dst_oui", "vlan_id", "tunnel_id", "ip_version",
                "udps.tcp_fin_mask",
                "application_name", "application_category_name", "application_is_guessed",
                "application_confidence", "requested_server_name", "client_fingerprint",
                "server_fingerprint", "user_agent", "content_type"]


# Kończy przepływ TCP po zakończeniu połączenia: po RST albo po FIN z obu stron i końcowym ACK.
#
# NFStream wywołuje on_init dla pierwszego pakietu przepływu i on_update dla kolejnych; pakiet
# jest już wliczony, a expiration_id = -1 zamyka przepływ po nim. Następny pakiet z tą samą
# piątką otwiera nowy przepływ.
class TcpTermination(NFPlugin):

    # pierwszy pakiet przepływu: zerujemy maskę FIN i sprawdzamy pakiet jak każdy kolejny
    def on_init(self, packet, flow):
        flow.udps.tcp_fin_mask = 0  # bit 0: FIN od źródła, bit 1: FIN od celu
        self._step(packet, flow)

    # każdy kolejny pakiet tego przepływu
    def on_update(self, packet, flow):
        self._step(packet, flow)

    # decyzja dla jednego pakietu TCP: RST kończy od razu, FIN zapamiętujemy w masce
    # (direction 0 = od źródła, 1 = od celu), a zwykły ACK bez danych po FIN z obu stron domyka połączenie
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
            flow.expiration_id = -1  # końcowy ACK po FIN z obu stron


# Liczy bajty danych (bez nagłówków) w każdym kierunku przepływu.
#
# Nie jest cechą modelu. Służy do etykiety „attempted”: połączenie ataku, w którym atakujący
# nie wysłał żadnych danych, np. odrzucone przez przeciążony serwer (Engelen i in. 2021; Liu i in. 2022).
class PayloadBytes(NFPlugin):

    # pierwszy pakiet: liczniki od zera, potem liczymy go jak każdy następny
    def on_init(self, packet, flow):
        flow.udps.src2dst_payload_bytes = 0
        flow.udps.dst2src_payload_bytes = 0
        self.on_update(packet, flow)

    # dodaje rozmiar danych pakietu do licznika jego kierunku
    def on_update(self, packet, flow):
        if packet.direction == 0:
            flow.udps.src2dst_payload_bytes += packet.payload_size
        else:
            flow.udps.dst2src_payload_bytes += packet.payload_size


# Pierwsza linia z wersją (editcap ma -V, reordercap tylko -h).
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


# editcap (pcap + deduplikacja) i reordercap. Zwraca (ścieżka, statystyka).
def prepare(src, tmpdir):
    deduped = os.path.join(tmpdir, "dedup.pcap")
    cmd = ["editcap", "-F", "pcap", "-w", str(DEDUP_WINDOW)]
    res = subprocess.run(cmd + [src, deduped], capture_output=True, text=True)
    if res.returncode != 0:
        sys.exit(f"editcap: {res.stderr.strip()}")
    stats = {"editcap": " ".join(res.stderr.split())[:300]}
    # editcap pisze na stderr np. „1000 packets seen, 3 packets skipped” - skipped to usunięte duplikaty
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


# Właściwa ekstrakcja: NFStream czyta przygotowany pcap i zwraca tabelę przepływów (jeden wiersz = jeden
# przepływ, ok. 70 kolumn statystyk). n_dissections=0 wyłącza DPI, statistical_analysis=True dokłada
# statystyki rozmiarów pakietów, odstępów i flag; udps to nasze dwie wtyczki z góry pliku.
def extract(pcap):
    streamer = NFStreamer(source=pcap, decode_tunnels=False, bpf_filter=BPF_FILTER,
                          idle_timeout=IDLE_TIMEOUT, active_timeout=ACTIVE_TIMEOUT,
                          n_dissections=0, statistical_analysis=True, udps=[TcpTermination(), PayloadBytes()])
    df = streamer.to_pandas()
    if df is None:  # NFStream zwraca None, gdy nie powstał żaden przepływ
        return pd.DataFrame()
    df = df.drop(columns=[c for c in DROP_COLUMNS if c in df.columns])
    # kolumny z wtyczek mają przedrostek udps. - zostawiamy krótkie nazwy
    df = df.rename(columns={"udps.src2dst_payload_bytes": "src2dst_payload_bytes",
                            "udps.dst2src_payload_bytes": "dst2src_payload_bytes"})
    # Kolejność chronologiczna jest potrzebna FlowTransformerowi (okna z kolejnych wierszy).
    # id NFStreama jako drugi klucz: przy tym samym czasie startu kolejność zostaje stała
    df = df.sort_values(["bidirectional_first_seen_ms", "id"], kind="stable").reset_index(drop=True)
    df["id"] = range(len(df))  # nowe id = pozycja po sortowaniu
    return df


# numery typów łącza z nagłówka pcap -> czytelne nazwy (do ostrzeżenia, gdy wyjdzie 0 przepływów)
LINKTYPE_NAMES = {1: "Ethernet", 113: "Linux cooked v1 (SLL)", 276: "Linux cooked v2 (SLL2)", 101: "raw IP"}


# Typ łącza z nagłówka pliku pcap (po editcap zawsze klasyczny pcap).
# Nagłówek ma 24 bajty; pierwsze 4 to „magiczna liczba”, z której widać kolejność bajtów
# (little albo big endian), a bajty 20-23 to typ łącza (górne bity to flagi, więc maska).
def linktype(pcap):
    with open(pcap, "rb") as f:
        hdr = f.read(24)
    if len(hdr) < 24:
        return None
    order = "<" if hdr[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    return struct.unpack(order + "I", hdr[20:24])[0] & 0x0FFFFFFF


# Lista plików do przetworzenia: wszystkie pcap/pcapng/cap z katalogu (także z podkatalogów)
# albo jeden podany plik.
def find_pcaps(path):
    if os.path.isdir(path):
        all_files = glob.glob(os.path.join(path, "**", "*"), recursive=True)
        files = [file for file in all_files if file.lower().endswith(PCAP_EXT)]
        return sorted(files)
    return [path]


# Dla każdego pliku: przygotowanie (deduplikacja, kolejność) w katalogu tymczasowym, ekstrakcja,
# zapis <nazwa>.parquet i <nazwa>.meta.json (wersje narzędzi, parametry, liczba duplikatów,
# sposoby zakończenia przepływów), żeby każdy wynik dało się później odtworzyć i sprawdzić.
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
    params = {"tcp_expiry": "both_fin", "idle": IDLE_TIMEOUT, "active": ACTIVE_TIMEOUT, "bpf": BPF_FILTER,
              "dpi": 0, "dedup_window": DEDUP_WINDOW}

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
            shutil.rmtree(tmpdir, ignore_errors=True)  # pliki pośrednie usuwamy także po błędzie
        out = os.path.join(args.out, f"{name}.parquet")
        df.to_parquet(out, index=False)
        # expiration_id mówi, jak przepływ się skończył (-1 = nasza wtyczka FIN/RST, 0 = idle, 1 = active);
        # liczności trafiają do meta.json jako kontrola, czy wtyczka działa
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
