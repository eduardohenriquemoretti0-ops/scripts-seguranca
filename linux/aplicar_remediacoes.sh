#!/bin/bash
# Remediações de segurança — Fratelli Moretti
# Rodar: bash aplicar_remediacoes.sh
set -e

echo "=== [2/9] SSH: desabilitar senha, MaxAuthTries 3 ==="
sudo sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
grep -q "^MaxAuthTries" /etc/ssh/sshd_config \
  && sudo sed -i 's/^MaxAuthTries.*/MaxAuthTries 3/' /etc/ssh/sshd_config \
  || echo "MaxAuthTries 3" | sudo tee -a /etc/ssh/sshd_config
sudo systemctl restart ssh
echo "SSH OK"

echo "=== [3/9] Postfix: loopback-only + corrigir mydestination ==="
sudo postconf -e 'inet_interfaces = loopback-only'
sudo postconf -e 'mydestination = $myhostname, localhost.localdomain, localhost'
sudo systemctl restart postfix
echo "Postfix OK"

echo "=== [4/9] pkexec: v124 já patcheado (PwnKit), mantendo SUID ==="
echo "Pulado — necessário para autenticação GNOME polkit"

echo "=== [5/9] pppd: remover SUID ==="
sudo chmod u-s /usr/sbin/pppd
echo "pppd SUID removido"

echo "=== [6/9] gnome-remote-desktop: desabilitar ==="
sudo systemctl disable --now gnome-remote-desktop.service 2>/dev/null || true
echo "gnome-remote-desktop desabilitado"

echo "=== [7/9] avahi-daemon: desabilitar ==="
sudo systemctl disable --now avahi-daemon.service avahi-daemon.socket 2>/dev/null || true
echo "avahi desabilitado"

echo "=== [8/9] cups-browsed: desabilitar (CVE-2024-47176) ==="
sudo systemctl disable --now cups-browsed.service 2>/dev/null || true
echo "cups-browsed desabilitado"

echo "=== [9/9] Atualizar hplip (security) + instalar lynis ==="
sudo apt-get update -qq
sudo apt-get upgrade -y hplip hplip-data libhpmud0 libsane-hpaio printer-driver-hpcups printer-driver-postscript-hp
sudo apt-get install -y lynis
echo "Pacotes OK"

echo ""
echo "=== VERIFICAÇÃO FINAL ==="
sudo ufw status
grep -E "^PasswordAuthentication|^MaxAuthTries|^PermitRootLogin" /etc/ssh/sshd_config
sudo postconf inet_interfaces
ls -la /usr/sbin/pppd | awk '{print $1, $NF}'
systemctl is-active gnome-remote-desktop avahi-daemon cups-browsed 2>/dev/null || true
echo "CONCLUÍDO."
