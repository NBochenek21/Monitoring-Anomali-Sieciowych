#!/usr/bin/env bash
# Pakiety usług dla środowiska Mininet (Ubuntu 22.04, WSL2), uruchamiać jako root.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y apache2 dnsmasq openssh-server openssh-client curl
# aiosmtpd (serwer poczty) instaluje install_wsl_packages.sh z requirements-extract.txt

# Usługi systemowe wyłączone: każdą uruchamiam ręcznie w przestrzeni nazw hosta Mininetu.
systemctl disable --now apache2 dnsmasq ssh >/dev/null 2>&1 || true

echo "apache2: $(apache2 -v | head -1 | awk '{print $3}')"
echo "dnsmasq: $(dnsmasq --version | head -1 | awk '{print $3}')"
echo "sshd:    $(/usr/sbin/sshd -V 2>&1 | head -1 || true)"
python3 - <<'PY'
import aiosmtpd
print("aiosmtpd:", aiosmtpd.__version__)
PY
