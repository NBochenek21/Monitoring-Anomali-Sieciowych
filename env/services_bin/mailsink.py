#!/usr/bin/env python3
"""Lekki serwer SMTP (aiosmtpd) na hoście "mail".

Przyjmuje pocztę od hostów biurowych i dopisuje ją do skrzynki mbox, żeby generować
realistyczny ruch SMTP (normalny wzorzec zachowania obok ataków). Nie przekazuje poczty
dalej. Pakiety idą przez r) do segmentu serwerów

    python3 mailsink.py --bind 10.0.10.14 --port 25 --mbox /tmp/lab/mail/inbox.mbox
"""
import argparse #opcje wiersza poleceń
import datetime # daty w skrzynce
import threading # blokada głównego wątku, gdy serwer działa w tle

from aiosmtpd.controller import Controller #biblioteka do tworzenia serwera SMTP

#gdy w rozmowie SMTP dzieje się coś konkretnego to woła metode handlera o umówionej nazwie, 
#ja definiuje tylko metode handle_DATA w momencie gdy klient prześle treść maila (po lini z kropka)
#reszta rozmowy ma domyślne zachowanie i każdy nadawca oraz odbiorca jest przyjomwany
#metoda jest asynchroniczna - zapisuje mail w formacie mbox
class MboxHandler:
    # zapamiętuje ścieżkę skrzynki, do której handle_DATA dopisuje maile
    def __init__(self, mbox_path):
        self.mbox_path = mbox_path

    #dzieki asynchronicznosci serwer może obsługiwać wielu klientów jednocześnie
    async def handle_DATA(self, server, session, envelope):
        ts = datetime.datetime.now().strftime("%a %b %d %H:%M:%S %Y") # skrót dnia tyg, skrót miesiąca, dzień, godzina:minuta:sekunda, rok
        with open(self.mbox_path, "a") as f: #appendujemy do pliku
            f.write(f"From {envelope.mail_from} {ts}\n") # zapisuje linie rozdziejająca wiadomości w formacie mbox
            for rcpt in envelope.rcpt_tos: #zapisuje linie z odbiorcami wiadomości w formacie mbox
                f.write(f"X-RcptTo: {rcpt}\n")
            f.write(envelope.content.decode("utf8", errors="replace")) #surowa tresc maila zmieniona na UTF-8
            f.write("\n\n")
        return "250 Message accepted for delivery" #kod SMTP oznaczający sukces

#parsuje argumenty (adres, port 25, sciezka szkrzynki; katalog na plik mbox tworzy services.py),
#a potem uruchamia serwer SMTP w pętli asynchronicznej. Zatrzymuje go services.py (SIGTERM)
def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    #tworzy parser argumentów z linii poleceń (docstring z modułu, mowi tez nie zwijaj i nie przeforatowuj tego opisu)

    parser.add_argument("--bind", required=True) #adres IP na którym serwer będzie nasłuchiwać
    parser.add_argument("--port", type=int, default=25)#konwertuje podana wartosc tekstu na liczbe
    parser.add_argument("--mbox", required=True)#sciezka do pliku skrzynki
    args = parser.parse_args() #odczytuje faktyczne argumentyprzekazane w lini poleceń

    #towrzymy controller z aiosmtpd - to on uruchamia właściwy serwer SMTP
    controller = Controller(MboxHandler(args.mbox), hostname=args.bind, port=args.port) 
    controller.start() #uruchamia serwer w osobnym wątku w tle
    threading.Event().wait() #blokuje głowny wątek; serwer działa w wątku kontrolera, a services.py kończy proces SIGTERM-em


if __name__ == "__main__":
    main()
