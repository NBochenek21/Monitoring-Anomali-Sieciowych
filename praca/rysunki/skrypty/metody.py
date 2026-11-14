"""Rysunki metod (rozdz. 3, 6, 7): oś czasu sesji M1, reguła okna etykiet, izolacja w Isolation Forest,
krzywa dobowa generatora ruchu i rozkład odstępów między sesjami (realizm). Wykresy wyników (rozdz. 10)
eksportuje się z dashboardu (przycisk aparatu: PNG w 4-krotnej rozdzielczości). Uruchamiać w Windows (matplotlib + pandas):
    python praca/rysunki/skrypty/metody.py
Oś czasu potrzebuje danych z dane_os_czasu.py (praca/rysunki/dane/)."""
import os
import sys

import numpy as np
import pandas as pd
from matplotlib.patches import Rectangle

from wspolne import DANE, MM, REPO, STATS, SZEROKOSC, liczba, plt, przecinek, zapisz

KODY = {"port_scan": "A1", "ssh_bruteforce": "A2", "dos_slow": "A3", "http_flood": "A4", "c2_beaconing": "Z1"}


def os_czasu(sesja="M1"):
    """Liczba przepływów w przedziałach 10 s (oś logarytmiczna) na tle okien ataków (rozdz. 6.5)."""
    counts = pd.read_csv(os.path.join(DANE, f"os_czasu_{sesja}.csv"), index_col="bin")
    okna = pd.read_csv(os.path.join(DANE, f"okna_{sesja}.csv"))
    fig, ax = plt.subplots(figsize=(SZEROKOSC, 62 * MM))
    minuty = counts.index / 60
    # kody ataków nad osią, na przemian w dwóch rzędach, żeby sąsiednie okna się nie nakładały
    for i, (_, w) in enumerate(okna.sort_values("start_s").iterrows()):
        ax.axvspan(w["start_s"] / 60, w["koniec_s"] / 60, color="0.88", lw=0)
        ax.text((w["start_s"] + w["koniec_s"]) / 120, 1.02 + 0.075 * (i % 2), KODY[w["typ"]], ha="center",
                va="bottom", fontsize=7.5, transform=ax.get_xaxis_transform())
    atak = counts["atak"]
    ax.bar(minuty, (atak - 0.8).clip(lower=0), bottom=0.8, width=10 / 60, align="edge", color="black",
           linewidth=0, label="przepływy ataków")
    ax.step(minuty, counts["normal"].clip(lower=0.8), where="post", color="0.45", lw=0.8, label="ruch normalny")
    ax.set_yscale("log")
    ax.set_ylim(0.8, 4000)
    ax.set_xlim(0, 60)
    ax.set_xlabel("czas sesji [min]")
    ax.set_ylabel("przepływy na 10 s")
    ax.set_yticks([1, 10, 100, 1000])
    ax.set_yticklabels(["1", "10", "100", "1000"])
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.28), ncol=3, frameon=False,
              handles=ax.get_legend_handles_labels()[0] + [Rectangle((0, 0), 1, 1, color="0.88")],
              labels=ax.get_legend_handles_labels()[1] + ["okno ataku (A1–A4, Z1)"])
    zapisz(fig, "os_czasu")


def regula_okna():
    """Schemat reguły etykiet: okno [start, koniec], końcówka (koniec, koniec + 2 s] (rozdz. 7.2)."""
    fig, ax = plt.subplots(figsize=(SZEROKOSC, 66 * MM))
    s, e, g = 2.0, 10.0, 2.0
    ax.add_patch(Rectangle((s, -0.6), e - s, 8.2, color="0.88", lw=0))
    ax.add_patch(Rectangle((e, -0.6), g, 8.2, facecolor="white", edgecolor="0.4", hatch="////", lw=0))
    # (start, koniec, tekst etykiety, opis); kropka = chwila startu przepływu, która decyduje o etykiecie
    przypadki = [
        (0.8, 3.5, "normalny", "start przed oknem"),
        (3.0, 4.6, "atak", "atakujący → cel, z danymi"),
        (4.4, 5.2, "atak", "cel → atakujący (np. resztka po RST)"),
        (6.0, 7.4, "attempted", "TCP bez danych od atakującego"),
        (5.0, 6.6, "normalny", "inny cel albo inny host"),
        (10.6, 10.9, "attempted", "końcówka: bez danych, do 2 s po oknie"),
        (11.0, 13.0, "normalny", "z danymi tuż po oknie"),
        (12.4, 13.6, "normalny", "start po końcówce"),
    ]
    for i, (a, b, etykieta, opis) in enumerate(przypadki):
        yy = 7 - i
        styl = {"atak": dict(facecolor="black"), "attempted": dict(facecolor="0.55"),
                "normalny": dict(facecolor="white")}[etykieta]
        ax.add_patch(Rectangle((a, yy - 0.28), b - a, 0.56, edgecolor="black", lw=0.6, **styl))
        ax.plot([a], [yy], "o", color="black", markersize=3, markeredgecolor="black", zorder=3)
        ax.text(14.3, yy, f"{etykieta}: {opis}", va="center", fontsize=8.5)
    for x, t in [(s, "start"), (e, "koniec"), (e + g, "koniec + 2 s")]:
        ax.axvline(x, color="black", lw=0.6)
        ax.text(x, 7.8, t, ha="center", va="bottom", fontsize=8.5)
    ax.set_xlim(0, 14)
    ax.set_ylim(-0.7, 8.4)
    ax.set_yticks([])
    ax.set_xticks([])
    ax.set_xlabel("czas (kropka: start przepływu, od którego zależy etykieta)")
    ax.grid(False)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.tick_params(top=False, right=False)
    zapisz(fig, "regula_okna")


def odmiana(n):
    """Polska odmiana słowa „podział” po liczebniku."""
    if n == 1:
        return "podział"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return "podziały"
    return "podziałów"


def izolacja(seed=7):
    """Losowe podziały izolujące punkt normalny i anomalię (rozdz. 3.1, idea Isolation Forest)."""
    rng = np.random.default_rng(3)
    dane = rng.normal(0, 1, size=(120, 2))
    normalny = np.array([0.15, -0.1])
    anomalia = np.array([3.4, 2.9])
    dane = np.vstack([dane, normalny, anomalia])
    fig, axes = plt.subplots(1, 2, figsize=(SZEROKOSC, 66 * MM))
    for ax, cel, tytul in [(axes[0], normalny, "punkt normalny"), (axes[1], anomalia, "anomalia")]:
        r = np.random.default_rng(seed)
        lo, hi = dane.min(axis=0) - 0.3, dane.max(axis=0) + 0.3
        punkty = dane.copy()
        podzialy = 0
        while len(punkty) > 1 and podzialy < 40:
            cecha = r.integers(2)
            wart = r.uniform(lo[cecha], hi[cecha])
            if cecha == 0:
                ax.plot([wart, wart], [lo[1], hi[1]], color="black", lw=0.6)
            else:
                ax.plot([lo[0], hi[0]], [wart, wart], color="black", lw=0.6)
            if cel[cecha] < wart:
                hi[cecha] = wart
            else:
                lo[cecha] = wart
            punkty = punkty[np.all((punkty >= lo) & (punkty <= hi), axis=1)]
            podzialy += 1
        ax.scatter(dane[:, 0], dane[:, 1], s=5, color="0.55", linewidths=0)
        ax.scatter([cel[0]], [cel[1]], s=28, color="black", marker="x", linewidths=1.2, zorder=3)
        ax.set_title(f"{tytul}: {podzialy} {odmiana(podzialy)}", pad=4)
        ax.set_xticks([])
        ax.set_yticks([])
        ax.grid(False)
        ax.tick_params(top=False, right=False)
    zapisz(fig, "izolacja_if")


def krzywa_dobowa():
    """Mnożnik intensywności sesji użytkowników w ciągu doby i godziny startu nagrań (rozdz. 6.3)."""
    sys.path.insert(0, os.path.join(REPO, "traffic"))
    import profiles
    krzywa = profiles.daily_curve()
    fig, ax = plt.subplots(figsize=(SZEROKOSC, 52 * MM))
    godziny = np.arange(24)
    ax.bar(godziny, krzywa, width=0.8, color="0.8", edgecolor="black", linewidth=0.5, align="edge")
    for h, nazwa in [(8, "M0, M1"), (9, "M2"), (10, "M3"), (11, "M4"), (13, "M5"), (14, "M6")]:
        ax.text(h + 0.4, krzywa[h] + 0.08, nazwa, ha="center", va="bottom", fontsize=7.5, rotation=90)
    ax.axhline(1.0, color="black", lw=0.6, linestyle="--")
    ax.set_xlim(0, 24)
    ax.set_ylim(0, max(krzywa) * 1.35)
    ax.set_xticks(range(0, 25, 2))
    ax.set_xlabel("godzina doby")
    ax.set_ylabel("mnożnik intensywności")
    przecinek(ax, "y")
    zapisz(fig, "krzywa_dobowa")


def realizm():
    """Odstępy między startami sesji użytkowników (znormalizowane) wobec rozkładu wykładniczego
    i odstępy heartbeatu IoT; wspólne dla obu wariantów (te same nagrania)."""
    gaps = pd.read_csv(os.path.join(STATS, "cic", "traffic_gaps.csv"))
    real = pd.read_csv(os.path.join(STATS, "cic", "traffic_realism.csv")).set_index("traffic")
    fig, axes = plt.subplots(1, 2, figsize=(SZEROKOSC, 55 * MM))
    user = gaps[gaps["traffic"] == "sesje użytkowników"]["gap"]
    axes[0].hist(user[user <= 6], bins=np.arange(0, 6.01, 0.25), density=True, color="0.8", edgecolor="black",
                 linewidth=0.4, label="odstępy w nagraniach")
    t = np.linspace(0, 6, 200)
    axes[0].plot(t, np.exp(-t), color="black", lw=1.0, label="rozkład wykładniczy")
    r = real.loc[[i for i in real.index if i.startswith("sesje")][0]]
    axes[0].set_title(f"sesje użytkowników (n = {int(r['gaps'])}, CV = {liczba(r['cv'], 3)}, "
                      f"D = {liczba(r['ks_d'], 3)})", fontsize=8.5)
    axes[0].set_xlabel("odstęp / średni odstęp hosta")
    axes[0].set_ylabel("gęstość")
    axes[0].legend(loc="upper right", fontsize=7.5)
    przecinek(axes[0])
    hb = gaps[gaps["traffic"] == "heartbeat IoT"]["gap"]
    r = real.loc[[i for i in real.index if i.startswith("heartbeat")][0]]
    axes[1].hist(hb, bins=30, color="0.8", edgecolor="black", linewidth=0.4)
    axes[1].set_title(f"heartbeat IoT (n = {int(r['gaps'])}, CV = {liczba(r['cv'], 3)})", fontsize=8.5)
    axes[1].set_xlabel("odstęp [s]")
    axes[1].set_ylabel("liczba odstępów")
    przecinek(axes[1])
    fig.tight_layout()
    zapisz(fig, "realizm_ruchu")


if __name__ == "__main__":
    os_czasu()
    regula_okna()
    izolacja()
    krzywa_dobowa()
    realizm()
