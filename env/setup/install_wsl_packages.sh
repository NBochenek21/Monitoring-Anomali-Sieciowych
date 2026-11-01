#!/usr/bin/env bash
# Instalacja pakietów środowiska w WSL2 (Ubuntu 22.04), uruchamiać jako root.
# Kolejność: ten skrypt, potem env/setup/install_services.sh i attacks/install_attack_tools.sh.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# Mininet i sieć (net-tools: Mininet sam używa ifconfig), nagrywanie i obróbka PCAP
# (wireshark-common: editcap, reordercap), dig, curl, pip i venv.
apt-get update
apt-get install -y \
  mininet openvswitch-switch \
  tcpdump ethtool iproute2 iputils-ping wireshark-common \
  net-tools dnsutils curl \
  python3-pip python3-venv

# IPv6 wyłączone na stałe w WSL: porty switchy Mininetu powstają w głównej przestrzeni nazw
# i od razu nie mają IPv6. Hosty Mininetu wyłączają IPv6 same (env/topology.py, LabHost),
# bo jądro nie przenosi tego ustawienia do nowych przestrzeni nazw. Bez tego pliku
# topology.build() kończy program z komunikatem.
cat > /etc/sysctl.d/90-lab-ipv6.conf <<'EOF'
# Laboratorium NIDS (praca inżynierska): IPv6 wyłączone w głównej przestrzeni nazw WSL.
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
EOF
sysctl -p /etc/sysctl.d/90-lab-ipv6.conf

# Systemowy python3: ekstrakcja przepływów i etykiety (features/).
pip3 install nfstream==6.6.0 pandas==2.3.3 pyarrow==25.0.1 numpy==2.2.6

# Osobne środowisko dla modeli (models/) i dashboardu (app/): FlowTransformer wymaga TensorFlow i Keras 3.
python3 -m venv /root/venvs/ft
/root/venvs/ft/bin/pip install tensorflow==2.21.0 keras==3.12.4 scikit-learn==1.6.1 scipy==1.15.3 \
  pandas==2.2.3 pyarrow==25.0.1 numpy==2.2.6 joblib==1.6.0 dash==4.4.1 plotly==7.1.0

echo "Gotowe: $(mn --version) / $(tcpdump --version 2>&1 | head -1)"
python3 -c "import nfstream; print('nfstream', nfstream.__version__)"
/root/venvs/ft/bin/python -c "import tensorflow, keras; print('tensorflow', tensorflow.__version__, '/ keras', keras.__version__)"
