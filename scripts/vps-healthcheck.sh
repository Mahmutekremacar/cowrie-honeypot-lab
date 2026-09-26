#!/usr/bin/env bash
# Health- und Acceptance-Check für den Honeypot-VPS
#
# Bündelt exakt die Prüfbefehle, die im Projekt nach jedem Reboot und für den
# finalen Acceptance-Test von Phase 1 verwendet wurden.
# Ausführen als Admin-User über die Tailscale-SSH-Sitzung (TCP/22222).
#
# Platzhalter: <WAZUH_TAILSCALE_IP>
set -uo pipefail

WAZUH_TS_IP="<WAZUH_TAILSCALE_IP>"

echo "=== 1. Dienste (erwartet: active x3) ==="
sudo systemctl is-active cowrie vector tailscaled

echo
echo "=== 2. Listener (erwartet: :22 -> twistd, :22222 -> sshd IPv4+IPv6, kein :2222) ==="
sudo ss -ltnp | grep -E ':22 |:2222 |:22222 ' || true

echo
echo "=== 3. Cowrie-Egress-Regel IPv4/IPv6 (erwartet: ESTABLISHED ACCEPT vor uid-owner 1001 REJECT) ==="
sudo iptables  -S ufw-before-output  | grep -E 'ESTABLISHED|uid-owner'
sudo ip6tables -S ufw6-before-output | grep -E 'ESTABLISHED|uid-owner'

echo
echo "=== 4. Route zum Home-SIEM (erwartet: dev tailscale0 src <HONEYPOT_TAILSCALE_IP>) ==="
ip route get "$WAZUH_TS_IP"

echo
echo "=== 5. Vector-Verbindung (erwartet: ESTAB von der Tailscale-IP, NICHT SYN-SENT von der Public-IP) ==="
sudo ss -tnp | grep "${WAZUH_TS_IP}:6514" || echo "WARNUNG: keine Vector-Verbindung gefunden"

echo
echo "=== 6. Containment-Test: Cowrie -> Internet (erwartet: GOOD) ==="
sudo -u cowrie timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/80' 2>/dev/null \
  && echo "BAD: Cowrie outbound succeeded" \
  || echo "GOOD: Cowrie outbound blocked"

echo
echo "=== 7. Containment-Test: Cowrie -> lokaler echter SSH (erwartet: GOOD) ==="
sudo -u cowrie timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/22222' 2>/dev/null \
  && echo "BAD: Cowrie reached real SSH" \
  || echo "GOOD: Cowrie cannot reach real SSH"

echo
echo "=== 8. Normaler Egress des Admin-Users (erwartet: HTTP 200) ==="
curl -sI --max-time 5 https://example.com | head -n 1
