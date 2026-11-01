# Skąd jest ten folder

**Cały folder `models/FlowTransformer/` to oryginalny kod autorów FlowTransformera z jedną udokumentowaną zmianą (lista niżej).**

| | |
|---|---|
| Repozytorium | https://github.com/liamdm/FlowTransformer |
| Wersja (commit) | `52236c8c9feccdeb44acf578789db7b8b36bacea` z 17.10.2023 („Updated extended_concepts.ipynb”) |
| Pobrano | 26.10.2026 |
| Licencja | GNU AGPL-3.0 (plik `LICENCE.txt`, zostaje w folderze) |
| Artykuł | Manocchio i in., „FlowTransformer: A Transformer Framework for Flow-based Network Intrusion Detection Systems”, Expert Systems with Applications 241 (2024), DOI 10.1016/j.eswa.2023.122564 |

Sprawdzenie przy pobraniu (26.10.2026): zawartość folderu porównana z repozytorium autorów (`diff -r`): identyczna. Usunąłem tylko ukryty folder `.git` z historią repozytorium autorów, żeby nie zagnieżdżać jednego repozytorium w drugim.

Ponowne sprawdzenie (2.11.2026, `diff -rq --strip-trailing-cr` z archiwum commita autorów): różni się tylko `encoder_block.py` (zmiana nr 1 niżej); doszedł ten plik `ZRODLO.md`. Pozostałe różnice to wyłącznie końce linii (Windows).

## Zasada zmian

- Plików w tym folderze nie zmieniam, dopóki nie jest to konieczne.
- Jeśli zmiana będzie konieczna (np. zgodność z Keras 3 w Colabie), każde zmienione miejsce dostanie komentarz zaczynający się od `# ZMIANA (praca inż.):` z opisem, co i dlaczego zmieniłem, a zmiana trafi do listy poniżej.

## Lista zmian w kodzie autorów

| # | Plik | Zmiana | Powód |
|---|---|---|---|
| 1 | `implementations/transformers/basic/encoder_block.py`, metoda `call` bloku `TransformerEncoderBlock` | `training` → `training=None` | Keras 3 (TensorFlow 2.21 w Colabie) nie przekazuje `training` przy budowie modelu; bez wartości domyślnej błąd „missing a required argument: 'training'” (26.10.2026) |

## Czego używam z tego folderu

Tylko architektury modelu, przez nasz plik `models/flowtransformer_model.py`:

- `implementations/input_encodings.py` → `RecordLevelEmbed`
- `implementations/transformers/basic_transformers.py` → `BasicTransformer` (i blok `TransformerEncoderBlock`)
- `implementations/classification_heads.py` → `LastTokenClassificationHead`
- `framework/flow_transformer.py` → `FlowTransformer.build_model` (składa model z powyższych klocków)
- `framework/model_input_specification.py`, `framework/flow_transformer_parameters.py`, `framework/enumerations.py` → opis wejść i parametrów

Przygotowania danych (`pre_processings.py`), pętli treningowej (`FlowTransformer.evaluate`) ani wczytywania danych (`load_dataset`) autorów nie używam; zastępuje je nasz kod (powód w `models/flowtransformer_model.py`).
