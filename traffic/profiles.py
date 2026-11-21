#!/usr/bin/env python3
"""Profile ruchu normalnego: krzywa dobowa, zachowania grup hostów, typy sesji.

Trzy filary (względnego)realizmu:
  1. rozkłady zamiast stałych: odstępy wykładnicze (proces Poissona), rozmiary log-normalne
     (pliki WWW: log-normalne z ogonem Pareto, services.py),
  2. profil dobowy: intensywność zależna od pory (krzywa znormalizowana do średniej 1),
  3. profile per grupa hostów: biuro, deweloperzy, administratorzy, drukarka, IoT.

Wszystko nagrane w czasie rzeczywistym
"""

# Krzywa dobowa: względna intensywność ruchu w kolejnych godzinach, znormalizowana do średniej 1
# w daily_curve(). DECYZJA WŁASNA - typowy dzień pracy biura: narastanie od 7, szczyt późnym
# porankiem (~10), dołek na lunch (~12-13), drugi szczyt po południu (~14-15), spadek po 17 i cisza
# w nocy. Oparte na jakościowej obserwacji, że ruch biurowy koncentruje się w godzinach pracy, a nocą
# zanika; kształt krzywej i dokładne wagi dobrałem sam (brak pewnego źródła z gotową krzywą)

#surowe wagi kolejnych godzin (przed normalizacją do średniej 1)
DAILY_RAW = [
    0.008, 0.005, 0.004, 0.004, 0.005, 0.010,  # 0-5 noc
    0.025, 0.055, 0.080, 0.095, 0.100, 0.092,  # 6-11 poranek, szczyt ok. 10
    0.060, 0.065, 0.090, 0.088, 0.070, 0.050,  # 12-17 dołek na lunch, popołudniowy szczyt ok. 14
    0.030, 0.020, 0.014, 0.010, 0.008, 0.006,  # 18-23 wieczór i noc
]

#Zwraca mnożnik intensywności dla każdej godziny: DAILY_RAW znormalizowane do średniej 1
def daily_curve():
    average = sum(DAILY_RAW) / len(DAILY_RAW)
    return [value / average for value in DAILY_RAW]

#zmienia czas od startu sesji na godzinę doby
#intensywność zmienia się skokowo co pełną godzinę - celowo: 
#przyjścia sesji użytkowników to proces Poissona ze stawką stałą w obrębie godziny
# Godzina doby (0-23) po elapsed_real_s sekundach od startu sesji


# Sesję nagrywam w czasie rzeczywistym, więc np. 2 h nagrania obejmuje 2 godziny doby;
# start_hour ustawia, od której godziny zaczyna się sesja (np. 8 rano)
def hour_of_day(elapsed_real_s, start_hour=0):
    return int((start_hour + elapsed_real_s / 3600.0) % 24)


#Zachowanie hosta (niezależne od segmentu): q1, q2 są w segmencie biuro, ale zachowują się inaczej.
#serwerow i hostów zewnętrzynych tu nie ma bo nie generują ruchu tylko odpowiadają
BEHAVIOR = {
    "o1": "office", "o2": "office", "o3": "office",
    "o4": "office", "o5": "office", "o6": "office",
    "q1": "printer",
    "q2": "iot",
    "d1": "dev", "d2": "dev", "d3": "dev",
    "a1": "admin", "a2": "admin",
}

#Profile grup: bazowa liczba sesji na godzinę (sph - sessions per hour) i wagi typów sesji
#Dla IoT zamiast sesji losowych jest heartbeat o stałym odstępie
#Obok sesji działa stałe tło (worker.background_loop)
#wartości sph to decyzja własna 
#To stawki BAZOWE: worker mnoży je przez krzywą dobową (średnia 1 na dobę), więc w godzinach
#nagrań 8-14 rzeczywista stawka jest 1,6-2,4 razy wyższa

GROUPS = {
    #sessions: wagi prawdopodobieństwa typu sesji
    "office": {"sph": 60, "sessions": {"web_browse": 0.55, "dns_lookup": 0.20, "mail_send": 0.25}},
    "dev":    {"sph": 24, "sessions": {"web_browse": 0.30, "ssh_work": 0.30, "file_transfer": 0.30,
                                       "dns_lookup": 0.10}},
    "admin":  {"sph": 36, "sessions": {"ssh_admin": 0.80, "dns_lookup": 0.20}},
    "printer": {"sph": 6, "sessions": {"dns_lookup": 0.5, "web_browse": 0.5}},
    "iot":    {"heartbeat_s": 60.0, "sessions": {}},
}

#Mikro-opóźnienie (think time) między akcjami w sesji -rozkład wykładniczy.
THINK_TIME_MEAN_S = 0.4

#pliki na serwerze web/xweb mają rozmiary ciężkoogonowe (generuje je services.py), a pobierane z
#popularnością typu Zipf
#nazwy i wagi trzymam tu, bo używa ich worker przy losowaniu pliku.
WEB_FILE_COUNT = 200 #serwer web
XWEB_FILE_COUNT = 40 #serwer "internetowy" (xweb)
ZIPF_EXPONENT = 0.8  #wykładnik to mój wybór

#zwraca liste nazw plików na serwerze web (albo xweb, gdy count=XWEB_FILE_COUNT)
def web_file_names(count=WEB_FILE_COUNT):
    return [f"file{i:04d}.bin" for i in range(1, count + 1)] 

#Wagi Zipf- jeden plik najpopularniejszy, kilka plików bardzo popularnych, a większość pobierana rzadko.
def zipf_weights(count=WEB_FILE_COUNT):
    return [1.0 / (rank ** ZIPF_EXPONENT) for rank in range(1, count + 1)]


#Polecenia SSH w ruchu normalnym- tylko odczyt - różne aby dawać różne ilościdanych w odp
SSH_COMMANDS = ["uptime", "ls -la /tmp", "cat /etc/hostname", "df -h", "whoami",
                "ps aux | head", "free -m", "date", "id", "cat /proc/loadavg"]

#nazwy DNS odpytywane w ruchu normalnym (wewnętrzne i "internetowe").
DNS_NAMES_INTERNAL = ["web.firma.lab", "mail.firma.lab", "files.firma.lab", "dns.firma.lab"]
#news. i cdn. rozwiązują się przez wildcard xdns na adres c2 (env/services.py), ale ruch HTTP tam nie idzie
DNS_NAMES_EXTERNAL = ["xweb.lab-ext.example", "news.lab-ext.example", "cdn.lab-ext.example"]
