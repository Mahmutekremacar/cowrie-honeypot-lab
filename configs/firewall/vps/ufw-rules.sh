#!/usr/bin/env bash
# UFW-Regeln des Honeypot-VPS – finaler, verifizierter Zustand (Phase 1)
#
# DOKUMENTATION, KEIN blind auszuführendes Skript.
# Die Reihenfolge beim Aufbau war entscheidend, um sich nicht auszusperren:
#   1. Solange der echte SSH-Dienst noch auf TCP/22 lief, war 22/tcp temporär
#      öffentlich erlaubt (Kommentar "TEMP real SSH ...").
#   2. Admin-SSH auf 22222 wurde zuerst über Tailscale freigegeben UND getestet.
#   3. Erst danach übernahm Cowrie Port 22; die alten 22/tcp-Regeln wurden durch
#      Regeln mit korrektem Zweck ersetzt.
#
# Platzhalter: <HONEYPOT_TAILSCALE_IP>, <ADMIN_TAILSCALE_IP>
set -euo pipefail

ADMIN_TS_IP="<ADMIN_TAILSCALE_IP>"        # vor Ausführung ersetzen
HONEYPOT_TS_IP="<HONEYPOT_TAILSCALE_IP>"  # vor Ausführung ersetzen

# Basis-Policy
sudo ufw default deny incoming
sudo ufw default allow outgoing   # Egress wird prozessbezogen für Cowrie eingeschränkt (before.rules)

# Echter OpenSSH (TCP/22222): NUR über das Tailscale-Interface und NUR von der Admin-Workstation.
# Es existiert bewusst KEINE allgemeine Freigabe für 22222.
sudo ufw allow in on tailscale0 \
  from "$ADMIN_TS_IP" \
  to "$HONEYPOT_TS_IP" \
  port 22222 proto tcp \
  comment 'Admin SSH from desktop via Tailscale'

# Öffentlicher Cowrie-Honeypot (TCP/22)
sudo ufw allow 22/tcp comment 'Public Cowrie SSH honeypot'

sudo ufw enable

# Erwartete Ausgabe von `sudo ufw status verbose` (verifiziert):
#
# Status: active
# Logging: on (low)
# Default: deny (incoming), allow (outgoing), disabled (routed)
#
# To                                              Action      From
# --                                              ------      ----
# <HONEYPOT_TAILSCALE_IP> 22222/tcp on tailscale0 ALLOW IN    <ADMIN_TAILSCALE_IP>  # Admin SSH from desktop via Tailscale
# 22/tcp                                          ALLOW IN    Anywhere              # Public Cowrie SSH honeypot
# 22/tcp (v6)                                     ALLOW IN    Anywhere (v6)         # Public Cowrie SSH honeypot
#
# Hinweis: Cowrie lauscht nur auf 0.0.0.0:22 (IPv4). Für IPv6 existiert auf Port 22
# kein Listener; die (v6)-Regel ist daher derzeit ohne Wirkung.
