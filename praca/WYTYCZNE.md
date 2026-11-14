# Lista kontrolna przed oddaniem pracy

Obowiązują: wzór strony tytułowej WIEiT („Strona tytułowa I stopień”, https://iet.agh.edu.pl/egzamin-dyplomowy/)
oraz wytyczne Instytutu Telekomunikacji (Sz. Szott, M. Grega, „Wytyczne do pisania prac dyplomowych”, 7.12.2021,
https://szymonszott.github.io/). Poniżej streszczenie wytycznych i sposób ich spełnienia w tym szablonie.

## Ustawione w klasie (`aghdpl.cls`), nie trzeba pilnować

- rysunki i tabele numerowane po kolei w całej pracy (Rys. 1, Rys. 2, ..., Tabela 1, ...),
- numeracja „1. Wstęp”, „1.1 Cel pracy”, „1.1.1 ...” (kropka tylko po numerze rozdziału),
- akapity wyjustowane, jednakowe wcięcie pierwszego wiersza (także pierwszego akapitu po tytule),
- streszczenie i abstract jako sekcje nienumerowane (`rozdzialy/streszczenie.tex`),
- przecinek dziesiętny w liczbach z `\num{}` i `\SI{}{}` (siunitx).

## Rysunki i tabele

- [ ] każdy rysunek, wykres i listing ma podpis; każda tabela nagłówek **nad** tabelą (`\caption` przed `tabular`),
- [ ] do każdego rysunku i tabeli jest odwołanie w tekście, przez numer: `na rysunku~\ref{fig:roc}`, nie „na powyższym rysunku”,
- [ ] rysunek lub tabela z innej pracy: przetłumaczona na polski, źródło w podpisie (`\cite{...}`),
- [ ] grafiki tylko wektorowe (PDF/SVG) albo PNG; **nie JPEG** (wykresy z dashboardu eksportować do PNG albo SVG).

## Tytuły i podpisy

- [ ] bez kropki ani dwukropka na końcu tytułu pracy, rozdziałów, podrozdziałów, nagłówków i podpisów,
- [ ] tytuły rozdziałów i podrozdziałów zaczynają się wielką literą,
- [ ] bez odwołań do literatury w tytułach,
- [ ] po tytule rozdziału kilka zdań wprowadzenia, dopiero potem pierwszy podrozdział,
- [ ] tytuł angielski pisany wielkimi literami według zasad dla tytułów angielskich.

## Styl

- [ ] jednostki ze spacją: `\SI{5}{\second}`, `\SI{5}{\kilo\bit\per\second}` (5 s, 5 kb/s), ale 50% bez spacji,
- [ ] jedna forma w całej pracy: strona bierna („W pracy przedstawiono...”) albo czynna; do ustalenia z promotorem,
- [ ] liczebniki mniejsze od 10 słownie („trzy algorytmy”),
- [ ] „liczba” (policzalne) i „ilość” (niepoliczalne) nie zamiennie: liczba przepływów, liczba sesji,
- [ ] unikać słowa „wykorzystać” i jego odmian (w tekście, np. „zastosować”, „użyć”); tytułu z USOS nie zmieniać,
- [ ] bez zwrotów potocznych,
- [ ] skrót wyjaśniony przy pierwszym użyciu (NIDS, FPR, AUC-ROC, ...),
- [ ] nazwy obcojęzyczne kursywą: `\obce{beaconing}`, `\obce{flow}`,
- [ ] spójne terminy (np. zawsze „przepływ”, zawsze „próg”; jedna nazwa dla jednego pojęcia),
- [ ] akapity: nie z jednego zdania i nie dłuższe niż 1/3 strony; zdania powiązane z poprzednimi,
- [ ] przejścia między rozdziałami: z podsumowania rozdziału wynika potrzeba następnego,
- [ ] półpauza jako `--` (np. `S1 -- S2`), cudzysłów polski: `\enquote{...}` albo „...”,
- [ ] jednolite czcionki w całej pracy.

## Bibliografia

- [ ] odwołanie przed kropką i po spacji: `... w zbiorze CIC-IDS2017~\cite{sharafaldin2018}.`,
- [ ] każda pozycja bibliografii ma odwołanie w tekście (biblatex drukuje tylko cytowane pozycje).

## Przed oddaniem

- [ ] sprawdzanie pisowni,
- [ ] brak podwójnych spacji, spacji przed przecinkiem i kropką, spacji po „(” i przed „)”, podwójnych kropek,
- [ ] spacja po kropce kończącej zdanie.
