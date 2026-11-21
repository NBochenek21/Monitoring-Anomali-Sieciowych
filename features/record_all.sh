#!/bin/bash
#nagranie sesji M0-M6 jedna po drugiej, po każdej: przepływy, etykiety, kontrola etykiet.
#to ten sam przepis, którym nagrano sesje do wyników pracy: czasy, godziny
#startu, ziarna i lista ataków M0 poniżej. Wynik każdej sesji w /root/sessions/<nazwa>/,
#wspólny log w /root/sessions/log.txt. Sesja trafia do data/flows/ tylko wtedy, gdy
#check_labels.py zwróci OK; wtedy dostaje też znacznik $OUT/OK. Ponowne uruchomienie pomija tylko
#sesje ze znacznikiem, a sesję bez niego (np. z błędem kontroli etykiet) nagrywa od nowa.
#
#  bash features/record_all.sh        #wszystkie sesje (sesje ze znacznikiem OK są pomijane)
#  bash features/record_all.sh M3     #tylko jedna sesja
cd "$(dirname "$0")/.." || exit 1
mkdir -p /root/sessions data/flows
LOG=/root/sessions/log.txt
ATTACKS_M0="A1_port_scan A2_ssh_bruteforce A3_slow_dos A4_http_flood"   #M0 bez Z1 (Z1 niewidziany)

#nazwa  czas[s]  godzina_startu  ziarno  ataki
SESSIONS="
M0 10800 8  100 m0
M1 3600  8  101 all
M2 3600  9  102 all
M3 3600  10 103 all
M4 3600  11 104 all
M5 3600  13 105 all
M6 3600  14 106 all
"

echo "== start $(date)" >> $LOG
echo "$SESSIONS" | while read -r NAME DURATION HOUR SEED ATTACKS; do
    [ -z "$NAME" ] && continue
    [ -n "$1" ] && [ "$NAME" != "$1" ] && continue
    OUT=/root/sessions/$NAME
    if [ -f "$OUT/OK" ]; then
        echo "== $NAME już nagrana i sprawdzona, pomijam" >> $LOG
        continue
    fi
    rm -rf "$OUT"
    if [ "$ATTACKS" = "m0" ]; then ATTACK_LIST=$ATTACKS_M0; else ATTACK_LIST=all; fi
    echo "== $NAME start $(date), $DURATION s, godzina $HOUR, ziarno $SEED, ataki: $ATTACK_LIST" >> $LOG
    #< /dev/null: Mininet w run_session.py czyta stdin i inaczej opróżniłby wejście tej pętli
    #kod różny od 0: wyjątek w trakcie sesji albo przerwa / cofnięcie czasu w nagraniu (kod 2);
    #takiej sesji nie przetwarzam, a brak znacznika OK sprawi, że następne uruchomienie nagra ją od nowa
    python3 features/run_session.py --duration "$DURATION" --attacks $ATTACK_LIST --start-hour "$HOUR" \
        --seed "$SEED" --out "$OUT" < /dev/null >> $LOG 2>&1
    CODE=$?
    if [ "$CODE" -ne 0 ]; then
        echo "== $NAME: BŁĄD nagrania (run_session.py, kod $CODE), sesja NIE trafia do data/flows/" >> $LOG
        continue
    fi
    if ! python3 features/extract_flows.py --pcap "$OUT/capture.pcap" --out "$OUT/flows" --tmp /tmp >> $LOG 2>&1; then
        echo "== $NAME: BŁĄD ekstrakcji przepływów, sesja NIE trafia do data/flows/" >> $LOG
        continue
    fi
    if ! python3 features/label_flows.py --flows "$OUT/flows" --ground-truth "$OUT/ground_truth.jsonl" \
            --out "$OUT/labeled.parquet" >> $LOG 2>&1; then
        echo "== $NAME: BŁĄD etykietowania, sesja NIE trafia do data/flows/" >> $LOG
        continue
    fi
    if python3 features/check_labels.py --labeled "$OUT/labeled.parquet" \
            --ground-truth "$OUT/ground_truth.jsonl" >> $LOG 2>&1; then
        #sesja dla modeli (run_experiments, run_s2); znacznik OK dopiero po udanym kopiowaniu
        if cp "$OUT/labeled.parquet" "data/flows/$NAME.parquet"; then
            touch "$OUT/OK"
        else
            echo "== $NAME: BŁĄD kopiowania do data/flows/, brak znacznika OK" >> $LOG
        fi
    else
        echo "== $NAME: BŁĄD kontroli etykiet, sesja NIE trafia do data/flows/" >> $LOG
    fi
    echo "== $NAME koniec $(date), pcap $(du -m "$OUT/capture.pcap" | cut -f1) MB" >> $LOG
done
echo "== wszystko gotowe $(date)" >> $LOG
