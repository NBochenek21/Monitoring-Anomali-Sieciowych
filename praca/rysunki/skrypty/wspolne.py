"""Wspólne ustawienia wykresów pracy: styl, przecinek dziesiętny, ścieżki, zapis PDF."""
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  #noqa: E402
from matplotlib.ticker import FuncFormatter  #noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RYSUNKI = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(RYSUNKI))
DANE = os.path.join(RYSUNKI, "dane")
STATS = os.path.join(REPO, "results", "stats")  #wyniki stats/summarize.py (realizm ruchu)
plt.style.use(os.path.join(HERE, "praca.mplstyle"))

MM = 1 / 25.4
SZEROKOSC = 160 * MM          #szerokość kolumny tekstu (aghdpl: A4, marginesy 30 i 20 mm)

#liczba z przecinkiem dziesiętnym (polska notacja)
def liczba(x, miejsca=None):
    if miejsca is None:
        tekst = f"{x:g}"
    else:
        tekst = f"{x:.{miejsca}f}"
    return tekst.replace(".", ",").replace("-", "\u2212")


#podpisy osi z przecinkiem dziesiętnym
def przecinek(ax, os_="both", miejsca=None):
    fmt = FuncFormatter(lambda v, _: liczba(v, miejsca))
    if os_ in ("x", "both"):
        ax.xaxis.set_major_formatter(fmt)
    if os_ in ("y", "both"):
        ax.yaxis.set_major_formatter(fmt)


def zapisz(fig, nazwa):
    sciezka = os.path.join(RYSUNKI, f"{nazwa}.pdf")
    fig.savefig(sciezka)
    plt.close(fig)
    print("zapisano", sciezka)
