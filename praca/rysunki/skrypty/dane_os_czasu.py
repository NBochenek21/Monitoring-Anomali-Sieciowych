"""Wyciąga do praca/rysunki/dane/ dane osi czasu sesji M1 (liczby przepływów w przedziałach 10 s
i okna ataków), żeby wykres dało się narysować bez pyarrow. Uruchamiać w WSL:
    /root/venvs/ft/bin/python praca/rysunki/skrypty/dane_os_czasu.py
"""
import json
import os

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
DANE = os.path.join(os.path.dirname(HERE), "dane")
SESJA = "M1"
BIN_S = 10

os.makedirs(DANE, exist_ok=True)
flows = pd.read_parquet(os.path.join(REPO, "data", "flows", f"{SESJA}.parquet"),
                        columns=["bidirectional_first_seen_ms", "attack_type"])
start = flows["bidirectional_first_seen_ms"].min() / 1000
flows["bin"] = ((flows["bidirectional_first_seen_ms"] / 1000 - start) // BIN_S).astype(int) * BIN_S
flows["grupa"] = flows["attack_type"].where(flows["attack_type"] == "normal", "atak")
counts = flows.groupby(["bin", "grupa"]).size().unstack(fill_value=0)
counts.to_csv(os.path.join(DANE, f"os_czasu_{SESJA}.csv"))
gt = [json.loads(line) for line in open(f"/root/sessions/{SESJA}/ground_truth.jsonl")]
okna = pd.DataFrame([{"typ": g["type"], "start_s": g["start"] - start, "koniec_s": g["end"] - start} for g in gt])
okna.to_csv(os.path.join(DANE, f"okna_{SESJA}.csv"), index=False)
print("zapisano", len(counts), "przedziałów i", len(okna), "okien")
