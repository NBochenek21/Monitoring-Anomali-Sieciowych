# Rysunki do pracy

- `zrodla/*.drawio`: źródła schematów (draw.io desktop); edytować w draw.io i zapisywać tutaj.
- `*.pdf`: wyeksportowane rysunki wstawiane do pracy (`\includegraphics`), też w repozytorium.
- `skrypty/`: skrypty matplotlib dla rysunków z osią czasu i danymi (wspólny styl `praca.mplstyle`).

## Zasady wyglądu

- Krój Times New Roman (taki jak tekst pracy z pakietu `times`), tekst 13 px w blokach i 12 px w opisach.
  Eksport PDF z draw.io: 1 px = 0,75 pt, więc 13 px ~ 9,75 pt, a 12 px = 9 pt przy wstawieniu w skali 1.
- Szerokość rysunku najwyżej 600 px (ok. 160 mm, szerokość kolumny tekstu w `aghdpl.cls`).
- Odcienie szarości `#E6E6E6`, `#B3B3B3`, `#666666`, czarne linie 1 px; wyróżnienia ramką przerywaną,
  nie samym kolorem (druk czarno-biały). Bez cieni (cienie draw.io zamieniają się w PDF na grafikę rastrową).
- Schematy draw.io bez tytułu i legendy wewnątrz rysunku: opis trafia do podpisu `\caption` w pracy.
  Na wykresach z danymi tytuły paneli i legenda zostają, bo rozróżniają panele i serie.

## Eksport i kontrola

```powershell
& "$env:LOCALAPPDATA\Programs\draw.io\draw.io.exe" --export --format pdf --crop --output topologia.pdf zrodla\topologia.drawio
pdffonts topologia.pdf    # krój TimesNewRoman..., kolumna emb = yes
```

## Wykresy (matplotlib)

Uruchamiać w Windows z katalogu głównego repozytorium (Python z matplotlib i pandas, czcionka Times New Roman z Windows):

```powershell
python praca\rysunki\skrypty\metody.py   # oś czasu M1, reguła okna, Isolation Forest, krzywa dobowa, realizm ruchu
```

Oś czasu sesji potrzebuje małych plików z `dane/`, wyciąganych z przepływów w WSL (pyarrow):
`/root/venvs/ft/bin/python praca/rysunki/skrypty/dane_os_czasu.py`.

## Wykresy wyników (rozdz. 10): z dashboardu

Zakładka "Porównanie", przycisk aparatu nad wykresem: PNG w 4-krotnej rozdzielczości (ok. 2800 px szerokości),
czcionka Times New Roman, przecinek dziesiętny; modele na krzywych ROC różnią się też stylem linii.
Zapisane pliki PNG umieszczać w tym katalogu (PNG jest dopuszczony przez wytyczne, JPEG nie).

## Wstawienie do pracy

```latex
\begin{figure}[htb]
  \centering
  \includegraphics{rysunki/topologia}  % skala 1: tekst rysunku ok. 9-10 pt
  \caption{Topologia sieci laboratoryjnej w Mininecie}
  \label{rys:topologia}
\end{figure}
```
