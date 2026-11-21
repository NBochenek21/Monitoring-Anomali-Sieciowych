#!/usr/bin/env bash
# Instalacja pakietów środowiska w WSL2 (Ubuntu 22.04), uruchamiać jako root.
# Kolejność: ten skrypt, potem env/setup/install_services.sh i attacks/install_attack_tools.sh.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Mininet i sieć (net-tools: mininet sam używa ifconfig), nagrywanie i obróbka PCAP
# (wireshark-common: editcap, reordercap), dig, curl, pip i venv. PyYAML pochodzi z apt (python3-yaml
# 5.4.1): z pip wersja 5.4.1 nie buduje się na Pythonie 3.10, a pip tylko uznaje wersję z apt za
# spełniającą wpis w requirements-extract.txt. Wersje apt nie są przypięte (Ubuntu usuwa stare wersje
# z repozytorium); wersje z wyników pracy są w env/setup/apt-versions.txt, porównuje je check_versions.sh.
apt-get update
apt-get install -y \
  mininet openvswitch-switch \
  tcpdump ethtool iproute2 iputils-ping wireshark-common \
  net-tools dnsutils curl \
  python3-pip python3-venv python3-yaml

# IPv6 wyłączone na stałe w WSL: porty switchy mininetu powstają w głównej przestrzeni nazw
# i od razu nie mają IPv6. Hosty minineta wyłączają IPv6 same (env/topology.py, LabHost),
# bo jądro nie przenosi tego ustawienia do nowych przestrzeni nazw. Bez tego pliku
# topology.build() kończy program z komunikatem.
cat > /etc/sysctl.d/90-lab-ipv6.conf <<'EOF'
# Laboratorium NIDS (praca inżynierska): IPv6 wyłączone w głównej przestrzeni nazw WSL.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
sysctl -p /etc/sysctl.d/90-lab-ipv6.conf

# Wersje pakietów Pythona są tylko w plikach requirements-*.txt w katalogu głównym repozytorium.
REPO="$(cd "$(dirname "$0")/../.." && pwd)"

# Systemowy python3: ekstrakcja przepływów, etykiety, ruch i ataki.
pip3 install -r "$REPO/requirements-extract.txt"

# Osobne środowisko dla modeli (models/), statystyki i dashboardu (app/): FlowTransformer wymaga TensorFlow i Keras 3.
python3 -m venv /root/venvs/ft
/root/venvs/ft/bin/pip install -r "$REPO/requirements-models.txt"

echo "Gotowe: $(mn --version) / $(tcpdump --version 2>&1 | head -1)"
python3 -c "import nfstream; print('nfstream', nfstream.__version__)"
/root/venvs/ft/bin/python -c "import tensorflow, keras; print('tensorflow', tensorflow.__version__, '/ keras', keras.__version__)"
