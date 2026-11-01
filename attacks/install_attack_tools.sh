#!/usr/bin/env bash
# Narzędzia ataków dla izolowanego laboratorium Mininet (Ubuntu 22.04, WSL2), jako root.
# Standardowe, powszechnie znane narzędzia; używane wyłącznie na własnych, testowych
# usługach w izolowanej sieci, z limitami intensywności, do zebrania etykietowanego
# zbioru do pracy obronnej (NIDS).
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y nmap patator slowhttptest python3-yaml python3-paramiko

echo "nmap:         $(nmap --version | head -1)"
echo "patator:      $(patator --version 2>&1 | head -1 || dpkg -s patator | grep -i version)"
echo "slowhttptest: $(slowhttptest -h 2>&1 | grep -i version | head -1 || dpkg -s slowhttptest | grep -i version)"
python3 -c "import yaml, paramiko; print('pyyaml + paramiko OK')"
# A4 (HTTP flood) i Z1 (C2 beaconing) używają własnych narzędzi w attacks/tools/ (tylko stdlib).
