%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% 
% File:     aghdpl.cls           (LaTeX Document class option "aghdpl")
%          
% Author:  Paweł Kłeczek      (pkleczek@agh.edu.pl)
%          Grzegorz J. Nalepa (gjn@agh.edu.pl)
%          Marcin Szpyrka     (mszpyrka@agh.edu.pl)
%          AGH University of Science and Technology, Kraków, POLAND
% 
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\message{*** [aghdpl.cls] ---  (PK, GJN, MSz)  v4.0 <2020-11-03>, strona tytulowa wg wzoru WIEiT 2023  ***}       

\newif\ifpdflatex\pdflatexfalse
\NeedsTeXFormat{LaTeX2e} % 
\ProvidesClass{aghdpl} 

\RequirePackage{kvoptions}

\DeclareStringOption[pl]{language}
\ProcessKeyvalOptions*

\DeclareOption{pdflatex}{\pdflatextrue}
\DeclareOption*{\PassOptionsToClass{\CurrentOption}{report}} 
\ProcessOptions\LoadClass[a4paper,twoside,openright]{report} 

\RequirePackage{xstring}


\newcommand{\ThesisLanguage}{pl}
\IfStrEqCase{\aghdpl@language}{%
	{en}{\renewcommand{\ThesisLanguage}{en}}%
	{pl}{\renewcommand{\ThesisLanguage}{pl}}%
}[\PackageError{aghdpl}{Invalid thesis language.}{Available languages: Polish (pl), English (en)}]


\RequirePackage{times}
\RequirePackage[T1]{fontenc}

% Lista wszystkich języków stanowiących języki pozycji bibliograficznych użytych w pracy.
% (Zgodnie z zasadami tworzenia bibliografii każda pozycja powinna zostać utworzona zgodnie z zasadami języka, w którym dana publikacja została napisana.)
\RequirePackage[english,polish]{babel}

% Użyj polskiego łamania wyrazów (zamiast domyślnego angielskiego).
\RequirePackage{polski}

% Użyj kodowania UTF-8.
\RequirePackage[utf8]{inputenc}

\RequirePackage{mathtools}
\RequirePackage{amsfonts}
\RequirePackage{amsmath}
\RequirePackage{amsthm}

\RequirePackage{graphicx}
\RequirePackage[usenames]{color}
\RequirePackage{url}
\RequirePackage{titlesec}
\RequirePackage{tocloft}

\RequirePackage[font=small, labelfont=bf, labelsep=period]{caption}
\RequirePackage{subcaption}
\RequirePackage{enumerate}
\RequirePackage{enumitem}

% =============================================================================
% SEC:   Ustawienia związane z formatowaniem tekstu
% =============================================================================

\RequirePackage{geometry}

\geometry{lmargin=30mm, rmargin=20mm, tmargin=30mm, bmargin=30mm, foot=10mm, head=10mm}  % rozmiary marginesów i nagłówka/stopki
\linespread{1.25}  % interlinia
\renewcommand{\labelitemi}{--}  % znak wypunktowania użyty w liście wypunktowania

\RequirePackage{indentfirst}  % wcięcie także pierwszego akapitu po tytule (jednakowe dla wszystkich)
\RequirePackage[all,defaultlines=2]{nowidow} % Kontrola sierot i wdów - działa lepiej niż \widowpenalty i \clubpenalty
\brokenpenalty=10000\relax

% =============================================================================
% SEC:   Polecenia wymagane m.in. do generowania strony tytułowej
% =============================================================================

\def\shorttitlePL#1   {\gdef\@shorttitlePL{#1}}
\def\shorttitleEN#1   {\gdef\@shorttitleEN{#1}}
\def\shortauthor#1    {\gdef\@shortauthor{#1}}
\def\titlePL#1        {\gdef\@titlePL{#1}}
\def\titleEN#1        {\gdef\@titleEN{#1}}
\def\faculty#1      {\gdef\@faculty{#1}}
\def\thesistype#1   {\gdef\@thesistype{#1}}
\def\supervisor#1   {\gdef\@supervisor{#1}}
\def\acknowledgements#1   {\gdef\@acknowledgements{#1}}
\def\department#1   {\gdef\@department{#1}}
\def\degreeprogramme#1 {\gdef\@degreeprogramme{#1}}

%------------------------------------------------------------------------------

\IfStrEqCase{\ThesisLanguage}{
	{pl}{%
		\def\thesisheaders{
			\fancyfoot[LE,RO]{\small \@shortauthor\quad\textit{\@shorttitlePL}}
		}
		
		\def\thesistable{
			\begin{tabular}{@{}p{55mm}l@{}}
				Autor: & {\itshape \@author}\\
				Kierunek studiów: & {\itshape \@degreeprogramme}\\
				Opiekun pracy: & {\itshape \@supervisor}\\
			\end{tabular}
		}
	}
	{en}{%
		\def\thesisheaders{
			\fancyfoot[LE,RO]{\small \@shortauthor\quad\textit{\@shorttitleEN}}
		}
		
		\def\thesistable{
			\begin{tabular}{@{}p{55mm}l@{}}
			Author: & {\itshape \@author}\\
			Degree programme: & {\itshape \@degreeprogramme}\\
			Supervisor: & {\itshape \@supervisor}\\
			\end{tabular}
		}
	}%
}

% Strona tytułowa według wzoru Wydziału Informatyki, Elektroniki i Telekomunikacji AGH
% (,,Strona tytułowa I stopień'', https://iet.agh.edu.pl/egzamin-dyplomowy/, plik z 10.2023):
% marginesy 2,5 cm, logo AGH z nazwą Uczelni, nazwa wydziału, instytut, typ pracy, tytuł polski
% i angielski, tabela (autor, kierunek, opiekun), miejsce i rok. Krój bezszeryfowy (Helvetica z pakietu
% times; wzór używa kroju Titillium z identyfikacji AGH).
\def\institute#1{\gdef\@institute{#1}}
\let\@acknowledgements\relax

\newcommand{\titlepages}{%
	\newgeometry{margin=25mm}
	\begin{titlepage}
		\sffamily
		\begin{center}
			\vspace*{8mm}
			\includegraphics[width=141mm]{agh_logo}\par
			\vspace{3mm}
			{\small\bfseries\MakeUppercase{\@faculty}\par}
			\ifdefined\@institute
				\vspace{4mm}
				{\small\@institute\par}
			\fi
			\vspace{16mm}
			{\fontsize{18}{22}\selectfont \@thesistype\par}
			\vspace{9mm}
			{\fontsize{16}{19}\selectfont\itshape
				\IfStrEqCase{\ThesisLanguage}{%
					{pl}{\@titlePL\par \@titleEN\par}
					{en}{\@titleEN\par \@titlePL\par}
				}
			}
		\end{center}
		\vspace{\fill}
		\noindent{\small\thesistable}
		\par\vspace{12mm}
		\begin{center}
			{\small Kraków, \@date}
		\end{center}
		\vspace*{25mm}
	\end{titlepage}
	\restoregeometry

	% Odwrocie strony tytułowej (druk dwustronny).
	\thispagestyle{empty}~\clearpage

	% Podziękowania tylko wtedy, gdy podano \acknowledgements{...} (wzór wydziału ich nie wymaga).
	\ifx\@acknowledgements\relax
		\setcounter{page}{3}
	\else
		\thispagestyle{empty}
		\vspace*{15cm}\vfill
		\begin{flushright}
			\begin{minipage}[!h]{10cm}
				{\Large\itshape \@acknowledgements}
			\end{minipage}
		\end{flushright}
		\clearpage
		\thispagestyle{empty}~\clearpage
		\setcounter{page}{5}
	\fi
}


% =============================================================================
% SEC:   Ustawienia nagłówków i stopek
% =============================================================================

\RequirePackage{fancyhdr}

\pagestyle{fancy}
\renewcommand{\chaptermark}[1]{\markboth{\thechapter.\ #1}{}}
\renewcommand{\sectionmark}[1]{\markright{\thesection.\ #1}}

\renewcommand{\headrulewidth}{0.5pt}
\renewcommand{\footrulewidth}{0.5pt}
\fancyhf{}
\fancyhead{}
\fancyhead[RE,LO]{\slshape{\small \rightmark}}
\fancyhead[RO,LE]{\bfseries \thepage}

\thesisheaders

\frenchspacing
\sloppy 
\flushbottom


% =============================================================================
% SEC:   Ustawienia formatowania tytułów rozdziałów, podrozdziałów, itd.
% =============================================================================

\titleformat{\chapter}[block]
{\bfseries\LARGE}{\filright \LARGE\thechapter. }{0ex}{}
%odstępy: lewy, góra, dół
\titlespacing{\chapter}{0pt}{17mm}{19mm}
\titleformat{\section}[block]
{\bfseries\Large}{\filright \Large\thesection\ }{0ex}{}
\titlespacing{\section}{7mm}{8mm plus 0mm minus 1mm}{4mm plus 0mm minus 1mm}
\titleformat{\subsection}[block]
{\bfseries\large}{\filright \large\thesubsection\ }{0ex}{}
\titlespacing{\subsection}{7mm}{6mm}{2.5mm}
\titleformat{\subsubsection}[block]
{\bfseries\normalsize}{\filright \normalsize\thesubsubsection\ }{0ex}{}
\titlespacing{\subsubsection}{7mm}{3mm}{1.5mm}

% Określ maksymalny poziom numeracji (głębsze poziomy nie będą miały numeru).
%   (np. 1 - chapter, 2 - section, itd.)
\setcounter{secnumdepth}{4}


% =============================================================================
% SEC:   Ustawienia generowania spisu treści i spisu rysunków
% =============================================================================

\renewcommand{\cfttoctitlefont}{\bfseries\Large}
\renewcommand{\cftbeforetoctitleskip}{20mm}
\renewcommand{\cftaftertoctitleskip}{19mm}
\renewcommand{\cftchapleader}{\cftdotfill{\cftdot}}
\renewcommand{\cftsecleader}{\cftdotfill{\cftdot}}
\renewcommand{\cftsubsecleader}{\cftdotfill{\cftdot}}
\renewcommand{\cftchapaftersnum}{.}
\renewcommand{\cftsecaftersnum}{}
\renewcommand{\cftsubsecaftersnum}{}
\setlength{\cftparskip}{2pt}
\setlength{\cftbeforechapskip}{0mm}
\renewcommand{\cftchappagefont}{\normalsize}


% =============================================================================
% SEC:   Ustawienia wyświetlania liczb (zgodne z polskimi zwyczajami typograficznymi)
% =============================================================================

\RequirePackage{siunitx}

\sisetup{
	output-decimal-marker = {,},  % symbol dziesiętny
	%	round-mode=places,
	%	round-precision=4,
	group-separator={~},  % separator grupy 3 cyfr
}

% =============================================================================
% SEC:   Ustawienia wyświetlania URL-i
% =============================================================================

% Zmiana kroju czcionki URL-i z czcionki o stałej szerokości na szeryfową z kursywą.
\renewcommand\UrlFont{\rmfamily\itshape}


% =============================================================================
% SEC:   Ustawienia podpisów pod ilustracjami
% =============================================================================

% Numeracja ciągła w całej pracy (Rys. 1, Rys. 2, ..., Tabela 1, ...), nie w obrębie rozdziału.
\counterwithout{figure}{chapter}
\counterwithout{table}{chapter}
% Nagłówek tabeli stoi nad tabelą: \caption pisze się przed tabular, a odstęp jest liczony pod podpisem.
\captionsetup[table]{position=above}
\captionsetup[subfigure]{labelfont=md}
\captionsetup{%
	% Użyj okrągłych nawiasów wokół odwołań do "podilustracji".
	subrefformat=parens,
	% Margines z obu stron podpisu.
	margin=2cm,
	% W przypadku podpisów mieszczących się w jednej linii nie stosuj justowania, tylko wyśrodkuj cały podpis.
	singlelinecheck=on,
}


% =============================================================================
%    SEC:   Konfiguracja bibliografii
% =============================================================================

\RequirePackage[
	style=numeric,
	sorting=none,
	%
	% Zastosuj styl wpisu bibliograficznego właściwy językowi publikacji.
	language=autobib,
	autolang=other,
	% Zapisuj datę dostępu do strony WWW w formacie RRRR-MM-DD.
	urldate=iso,
	seconds=true,  % wymagane przez urldate=iso
	% Nie dodawaj numerów stron, na których występuje cytowanie.
	backref=false,
	% Podawaj ISBN.
	isbn=true,
	% Nie podawaj URL-i, o ile nie jest to konieczne.
	url=false,
	%
	% Ustawienia związane z polskimi normami dla bibliografii.
	maxbibnames=3,
	% Wybór silnika generowania bibliografii:
%	backend=bibtex  % - jeżeli używamy BibTeX-a
	backend=biber   % - jeżeli używamy biber-a
]{biblatex}

\RequirePackage{csquotes}
% Ponieważ `csquotes` nie posiada polskiego stylu, można skorzystać z mocno zbliżonego stylu chorwackiego.
\DeclareQuoteAlias{croatian}{polish}

\addbibresource{bibliografia.bib}

% Nie wyświetlaj wybranych pól.
%\AtEveryBibitem{\clearfield{note}}

\DeclareFieldFormat*{title}{,,\textit{#1}''}


% =============================================================================
%    SEC:   Konfiguracja listingów
% =============================================================================

% Użyj czcionki kroju Courier.
\RequirePackage{courier}

\RequirePackage{listings}
\lstloadlanguages{TeX}

\lstset{
	literate={ą}{{\k{a}}}1
           {ć}{{\'c}}1
           {ę}{{\k{e}}}1
           {ó}{{\'o}}1
           {ń}{{\'n}}1
           {ł}{{\l{}}}1
           {ś}{{\'s}}1
           {ź}{{\'z}}1
           {ż}{{\.z}}1
           {Ą}{{\k{A}}}1
           {Ć}{{\'C}}1
           {Ę}{{\k{E}}}1
           {Ó}{{\'O}}1
           {Ń}{{\'N}}1
           {Ł}{{\L{}}}1
           {Ś}{{\'S}}1
           {Ź}{{\'Z}}1
           {Ż}{{\.Z}}1,
	basicstyle=\footnotesize\ttfamily,
}


% =============================================================================
%    SEC:   Konfiguracja tabel
% =============================================================================

\RequirePackage{array}
\RequirePackage{tabularx}
\RequirePackage{multirow}
\RequirePackage{booktabs}
\RequirePackage{makecell}
\RequirePackage[flushleft]{threeparttable}

% defines the X column to use m (\parbox[c]) instead of p (`parbox[t]`)
\newcolumntype{C}[1]{>{\hsize=#1\hsize\centering\arraybackslash}X}

% =============================================================================
%    SEC:   INNE
% =============================================================================

% Nazwa obcojęzyczna w tekście (wytyczne: kursywą), np. \obce{backoff}.
\newcommand{\obce}[1]{\textit{#1}}

% Pusta strona wstawiana przed rozdziałem (druk dwustronny, rozdział od strony nieparzystej)
% bez nagłówka i stopki.
\renewcommand{\cleardoublepage}{%
	\clearpage
	\if@twoside\ifodd\c@page\else\hbox{}\thispagestyle{empty}\newpage\fi\fi
}

\newcommand{\RedefinePlainStyle}{%
	% Ponowne zdefiniowanie stylu `plain`, aby usunąć numer strony z pierwszej strony spisu treści i poszczególnych rozdziałów.
	\fancypagestyle{plain}
	{
		% Usuń nagłówek i stopkę
		\fancyhf{}
		% Usuń linie.
		\renewcommand{\headrulewidth}{0pt}
		\renewcommand{\footrulewidth}{0pt}
	}
}

\AtBeginDocument{
	\renewcommand{\tablename}{Tabela}
	\renewcommand{\figurename}{Rys.}
}

% =============================================================================
% SEC:   Niestandardowe środowiska
% =============================================================================

% ----------------------------------------------------------------------------
%    Środowisko do tworzenia opisów symboli użytych w równaniu
% ----------------------------------------------------------------------------

\SetLabelAlign{parright}{\parbox[t]{\labelwidth}{\raggedleft#1}}
\setlist[description]{style=multiline, topsep=10pt, align=parright}

% Odstęp po obu stronach półpauzy.
\newlength{\descriptiondashgap}
\setlength{\descriptiondashgap}{0.5em}

% Element na liście symboli matematycznych użytych w równaniu (symbol wyrównany do prawej, oddzielony półpauzą od definicji)
\renewcommand*\descriptionlabel[1]{\hspace \labelsep \normalfont \bfseries #1 \mdseries\hspace{\descriptiondashgap}--\hspace{\descriptiondashgap}}

% Odległość półpauzy od lewego marginesu.
\newlength{\eqwheremargin}
\setlength{\eqwheremargin}{2cm}

\newenvironment{eqwhere}[1][]
{%
	\setlength{\eqwheremargin}{#1}%
	\begin{description}[leftmargin=\eqwheremargin, itemsep=0cm, labelsep=0cm]
}
{\end{description}}
