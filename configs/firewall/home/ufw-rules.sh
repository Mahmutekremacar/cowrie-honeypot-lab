#!/usr/bin/env bash
# UFW-Regeln des Home-SIEM-Servers – finaler, verifizierter Zustand (Phase 1)
#
# DOKUMENTATION, KEIN blind auszuführendes Skript.
#
# Bewusste Designentscheidung:
#   Die globale Default-Policy bleibt vorerst "allow incoming".
#   Vor dem Projekt war UFW auf dem Home-Server inaktiv, und der Server bedient
#   bereits andere Systeme (Wazuh-Agents auf 1514/1515, Dashboard 443, API 55000,
#   SSH 22). Ein sofortiges "default deny incoming" ohne vorherige Inventarisierung
#   der legitimen Quellen hätte das bestehende Wazuh-Lab beschädigen können.
#
#   Stattdessen wird die Honeypot-Identität gezielt eingeschränkt:
#   ein explizites Allow (nur TCP/6514) gefolgt von einem Deny für alles andere.
#   Die Reihenfolge ist entscheidend – UFW wertet die erste passende Regel aus.
#
#   Die Umstellung des gesamten Home-Servers auf default-deny ist als eigener
#   Härtungsschritt (Phase 2 / Folgearbeit) vorgesehen.
#
# Platzhalter: <HONEYPOT_TAILSCALE_IP>, <WAZUH_TAILSCALE_IP>
set -euo pipefail

HONEYPOT_TS_IP="<HONEYPOT_TAILSCALE_IP>"  # vor Ausführung ersetzen
WAZUH_TS_IP="<WAZUH_TAILSCALE_IP>"        # vor Ausführung ersetzen

sudo ufw default allow incoming
sudo ufw default allow outgoing

# [1] Einziger erlaubter Pfad des Honeypots: Log-Ingestion auf TCP/6514
sudo ufw allow in on tailscale0 \
  from "$HONEYPOT_TS_IP" \
  to "$WAZUH_TS_IP" \
  port 6514 proto tcp \
  comment 'Honeypot log ingestion'

# [2] Alles andere vom Honeypot über tailscale0 blockieren
sudo ufw deny in on tailscale0 \
  from "$HONEYPOT_TS_IP" \
  comment 'Block honeypot from other home services'

sudo ufw enable

# Erwartete Ausgabe von `sudo ufw status numbered` (verifiziert):
#
# [ 1] <WAZUH_TAILSCALE_IP> 6514/tcp on tailscale0 ALLOW IN  <HONEYPOT_TAILSCALE_IP>  # Honeypot log ingestion
# [ 2] Anywhere on tailscale0                      DENY IN   <HONEYPOT_TAILSCALE_IP>  # Block honeypot from other home services
