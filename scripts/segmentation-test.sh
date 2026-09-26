#!/usr/bin/env bash
# Segmentierungstest: Was darf der Honeypot im Home-Netz erreichen?
#
# Auf dem HONEYPOT-VPS ausführen (nicht auf dem Home-Server!).
# Lessons Learned aus dem Projekt: Ein erster Testlauf wurde versehentlich auf dem
# Home-Server selbst ausgeführt; dort "funktionieren" alle Ports, weil der Server
# seine eigene Tailscale-IP anspricht. Deshalb prüft das Skript den Hostnamen.
#
# Interpretation:
#   timed out           -> von Tailscale-Policy/Firewall blockiert (gewünscht)
#   Connection refused  -> Pfad erlaubt, aber kein Dienst lauscht
#   succeeded           -> Pfad erlaubt und Dienst erreichbar
#
# Erwartung (verifiziert in Phase 1):
#   22, 443, 1514, 1515, 55000 -> timed out
#   6514                       -> succeeded (vor Installation des Receivers: Connection refused)
#
# Platzhalter: <WAZUH_TAILSCALE_IP>
set -uo pipefail

WAZUH_TS_IP="<WAZUH_TAILSCALE_IP>"
EXPECTED_HOST_HINT="honeypot"   # an den eigenen VPS-Hostnamen anpassen

if ! hostname | grep -qi "$EXPECTED_HOST_HINT"; then
  echo "WARNUNG: Hostname '$(hostname)' – läuft dieses Skript wirklich auf dem Honeypot-VPS?"
fi

echo "=== Muss BLOCKIERT sein ==="
for port in 22 443 1514 1515 55000; do
  nc -zvw3 "$WAZUH_TS_IP" "$port"
done

echo
echo "=== Muss ERLAUBT sein (Log-Pfad) ==="
nc -zvw3 "$WAZUH_TS_IP" 6514
