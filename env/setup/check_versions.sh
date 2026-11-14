#!/usr/bin/env bash
# Porównuje zainstalowane wersje pakietów apt z env/setup/apt-versions.txt (wersje, w których
# nagrano sesje i policzono wyniki pracy) i wypisuje różnice. Kod wyjścia 0 = wszystko zgodne,
# 1 = są różnice (wtedy wynik może się nieznacznie różnić; różnice warto zapisać przy wynikach).
#   bash env/setup/check_versions.sh
set -uo pipefail
FILE="$(cd "$(dirname "$0")" && pwd)/apt-versions.txt"
differences=0
while IFS=$'\t' read -r package expected; do
    case "$package" in ''|\#*) continue ;; esac
    installed=$(dpkg-query -W -f='${Version}' "$package" 2>/dev/null || echo "brak")
    if [ "$installed" != "$expected" ]; then
        echo "RÓŻNICA  $package: zainstalowane $installed, w pracy $expected"
        differences=1
    fi
done < "$FILE"
# tcpdump wołany jest ścieżką /usr/bin/tcpdump (env/topology.py), ale inny tcpdump w PATH
# (np. z pakietu pfring w /usr/local/bin) łatwo pomylić przy ręcznych poleceniach
if [ "$(command -v tcpdump)" != "/usr/bin/tcpdump" ]; then
    echo "UWAGA    tcpdump w PATH to $(command -v tcpdump), nagrania używają /usr/bin/tcpdump"
fi
[ "$differences" -eq 0 ] && echo "Wersje pakietów apt zgodne z apt-versions.txt."
exit "$differences"
