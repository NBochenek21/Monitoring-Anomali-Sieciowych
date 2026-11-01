# Detekcja anomalii w ruchu sieciowym: klasyczne ML vs FlowTransformer

Kod do pracy inżynierskiej „Wykorzystanie algorytmów uczenia maszynowego oraz modeli transformatorowych w detekcji anomalii w ruchu sieciowym”.

Emulowana sieć małej firmy (Mininet) z ruchem normalnym i atakami, nagrywanie na routerze, przepływy NFStream z etykietami (jedna reguła dla Mininetu, CIC-IDS2017 i GeNIS), cztery detektory (baseline progowy, Isolation Forest, Random Forest, FlowTransformer) w scenariuszach S0/S1/S2, statystyczne porównanie modeli i dashboard Dash w trybie replay.

## Struktura

| Katalog | Zawartość |
| --- | --- |
| `env/` | topologia Mininetu (router r0 + 5 segmentów), usługi, skrypty instalacji |
| `traffic/` | generator ruchu normalnego (proces Poissona, krzywa dobowa, grupy hostów) |
| `attacks/` | orkiestrator ataków A1–A4 i Z1 (scenariusze YAML, ground truth) |
| `features/` | nagranie sesji, ekstrakcja przepływów, etykiety, cechy kontekstu hosta |
| `models/` | modele, scenariusze S0/S1 (`run_experiments.py`) i S2 (`run_s2.py`); `FlowTransformer/` to kod autorów (AGPL-3.0, pochodzenie w `ZRODLO.md`) |
| `stats/` | porównanie modeli po sesjach (średnia ± 95% przedział ufności, wyniki per sesja, recall per atak, S2 wobec S1) i realizm ruchu |
| `app/` | dashboard Dash |

## Uruchomienie

Windows 11 + WSL2 (`Ubuntu-22.04`, użytkownik root). Instalacja w tej kolejności: `env/setup/install_wsl_packages.sh`, `env/setup/install_services.sh`, `attacks/install_attack_tools.sh` (wersje pakietów przypięte w skryptach). Dwa środowiska Pythona 3.10: ekstrakcja, etykiety, ruch i ataki w systemowym `python3` (`requirements-extract.txt`), a modele, statystyka i dashboard w `/root/venvs/ft/bin/python` (`requirements-models.txt`).

Wszystkie komendy uruchamia się w WSL jako root, z katalogu głównego repozytorium:

```bash
wsl -d Ubuntu-22.04 -u root
cd <katalog repozytorium>          # np. /mnt/c/Users/<użytkownik>/<repozytorium>
```

### 1. Środowisko (sieć i usługi)

```bash
python3 env/topology.py                  # test sieci: 6 sprawdzeń (pingall, IPv6, offloading, RTT LAN/WAN, nagrywanie)
python3 env/topology.py --cli            # po testach konsola Mininetu
python3 env/services.py                  # test usług: web, DNS, SSH, SFTP, poczta, xweb, C2
```

### 2. Nagranie sesji (ruch normalny + ataki)

```bash
# krótka sesja próbna z dwoma atakami (ok. 15 min)
python3 features/run_session.py --duration 900 --attacks A2_ssh_bruteforce A4_http_flood --out /root/test

# wszystkie sesje M0-M6 z czasami i ziarnami użytymi w pracy (po każdej: przepływy, etykiety, kontrola)
bash features/record_all.sh
bash features/record_all.sh M1           # tylko jedna sesja
```

### 3. Przepływy, etykiety i ich kontrola (jedna sesja krok po kroku)

```bash
python3 features/test_extract_flows.py   # test zamykania przepływów TCP na syntetycznych PCAP-ach
python3 features/extract_flows.py --pcap /root/sessions/M1/capture.pcap --out /root/sessions/M1/flows
python3 features/label_flows.py --flows /root/sessions/M1/flows --ground-truth /root/sessions/M1/ground_truth.jsonl --out /root/sessions/M1/labeled.parquet
python3 features/check_labels.py --labeled /root/sessions/M1/labeled.parquet --ground-truth /root/sessions/M1/ground_truth.jsonl
cp /root/sessions/M1/labeled.parquet data/flows/M1.parquet
```

### 4. Zbiory publiczne (CIC-IDS2017, GeNIS)

```bash
python3 features/extract_flows.py --pcap data/datasety/CIC-IDS2017 --out data/flows_raw/cic
python3 features/label_cic.py --flows data/flows_raw/cic --ground-truth features/cic_ground_truth/official.csv --out data/flows/cic.parquet
python3 features/extract_flows.py --pcap data/datasety/GeNIS --out data/flows_raw/genis
python3 features/label_genis.py --flows data/flows_raw/genis --ground-truth data/datasety/GeNIS/0-info/genis-ground-truth.csv --out data/flows/genis.parquet
```

### 5. Modele: scenariusze S0, S1, S2

```bash
SESJE="data/flows/M1.parquet data/flows/M2.parquet data/flows/M3.parquet data/flows/M4.parquet data/flows/M5.parquet data/flows/M6.parquet"
# S0 i S1 (wariant CIC; dla wariantu CIC + GeNIS dopisać data/flows/genis.parquet po cic.parquet)
/root/venvs/ft/bin/python models/run_experiments.py --source data/flows/cic.parquet --sessions $SESJE
# S2: adaptacja na sesji M0 (wymaga modeli z S1)
/root/venvs/ft/bin/python models/run_s2.py --source data/flows/cic.parquet --adaptation data/flows/M0.parquet --sessions $SESJE
```

### 6. Statystyka i realizm ruchu

```bash
/root/venvs/ft/bin/python stats/summarize.py --variant cic --traffic /root/sessions/M1 /root/sessions/M2 /root/sessions/M3 /root/sessions/M4 /root/sessions/M5 /root/sessions/M6
/root/venvs/ft/bin/python stats/summarize.py --variant cic+genis --traffic /root/sessions/M1 /root/sessions/M2 /root/sessions/M3 /root/sessions/M4 /root/sessions/M5 /root/sessions/M6
```

### 7. Dashboard (tryb replay)

```bash
/root/venvs/ft/bin/python app/dashboard.py --predictions results/raw/S1_cic_M1 --ground-truth /root/sessions/M1/ground_truth.jsonl --stats results/stats/cic
```

Potem w przeglądarce w Windows: http://localhost:8050. W pasku bocznym wybiera się scenariusz (S1 bez adaptacji albo S2 po adaptacji na M0), wariant modeli i sesję testową; nad widokami jest napis, który bieg jest odtwarzany. Predykcje S1 zapisuje `run_experiments.py`, a S2 `run_s2.py` (`results/raw/<scenariusz>_<wariant>_<sesja>/`). Zatrzymanie: Ctrl+C.

Dane (`data/`), nagrania, wytrenowane modele i predykcje (`results/raw/`) nie są w repozytorium; w `results/` są tylko małe pliki CSV z wynikami. Kod uruchamiać tylko w izolowanym laboratorium w WSL: działa jako root, zawiera testowe hasło i narzędzia ataków.

Opis decyzji, źródła, wyniki i plan części opisowej pracy są w Notion („Praca inżynierska: blueprint (opis, decyzje, źródła)”).
