# Phase 2 – Detection Engineering, Threat Analysis und SOC Dashboarding

> **Status: in Arbeit.** ✔ = erledigt · ◐ = teilweise · ⏳ = offen. Datenbasis der erledigten Punkte: 23.–26.09.2026.

## A. Wazuh-Dashboard „Cowrie Honeypot SOC"

- [x] Total Connections, Successful Cowrie Logins, Commands Observed, Connections Over Time, Top Source IPs, Top Usernames, Top Passwords, Top Commands
- [ ] „Commands Observed“ und „Top Commands“ auf `rule.groups:cowrie_command` umstellen (nötig seit Regelwerk v2)
- [ ] Unique Source IPs, Event Types
- [ ] Payload-Aktivität (110215/110221/110217), Blocked Downloads, Tunnel-/Proxy-Versuche
- [ ] MITRE ATT&CK Overview, High-Severity-Kommandos
- [ ] Recent Attacker Activity, Session-Drilldown
- [ ] eigene Test-IPs und `127.0.0.1` filtern
- [ ] Export der Saved Objects (NDJSON) nach `wazuh/dashboard/`

Spezifikation: [`../wazuh/dashboard/README.md`](../wazuh/dashboard/README.md)

## B. Detection Engineering

- [x] Regelwirkung auf ~2,5 Tagen realer Telemetrie gemessen
- [x] 110216 korrigiert (Falsch-Positive durch Shell-Umleitungen) → neue Regel 110220
- [x] Sichtbarkeitslücke „gescheiterter Download“ geschlossen → 110221
- [x] neue Regeln: Tunnel/Proxy (110222), Download-an-Shell (110223), eingebetteter Private Key (110224), `chmod +x` (110225), System Discovery (110226)
- [x] 110219 neu definiert (alle Login-Versuche statt nur Fehl-Logins, Schwelle 20/5 min anhand realer Daten gewählt)
- [x] Untergruppen für Dashboards, Regressionstest-Harness mit 15 Testfällen
- [ ] **Tests mit dem echten Regelwerk ausführen** (`wazuh/logtest/run-tests.sh`) und Ergebnis dokumentieren
- [ ] 110219 manuell testen (frequency-Regel)
- [ ] Lücken aus [`mitre-mapping.md`](mitre-mapping.md#3-lücken-und-backlog): Spurenbeseitigung (T1070.004), Tarnnamen bei Uploads (T1036.005), `last` (T1033), K3-Signatur
- [ ] Entscheidung zur Cowrie-Benutzerdatenbank dokumentieren (aktuell 99,7 % akzeptierte Logins: maximale Kommando-Sichtbarkeit vs. realistisches Brute-Force-Bild)

## C. Real Attacker Investigation

- [x] [HP-001](../investigations/HP-001.md) – curl/Perl-Dropper, Egress-Sperre wirksam
- [x] [HP-002](../investigations/HP-002.md) – Shell-Fingerprinting
- [x] [HP-003](../investigations/HP-003.md) – SSH-Key-Dropper
- [x] [HP-004](../investigations/HP-004.md) – SFTP-Upload „sshd“
- [ ] Hash-Reputation für das ELF aus HP-004 per Lookup (ohne Upload) nachtragen
- [ ] weitere Untersuchung nach längerer Laufzeit (z. B. erste Persistenzversuche)

## D. MITRE ATT&CK Mapping

- [x] beobachtete Aktivität → 12 Techniken, Coverage-Matrix, Lücken ([`mitre-mapping.md`](mitre-mapping.md))
- [ ] optional: ATT&CK-Navigator-Layer exportieren

## E. Dashboard und Screenshots

- [ ] anonymisierte Screenshots gemäß [`../screenshots/README.md`](../screenshots/README.md)

## F. Härtung / offene Punkte aus Phase 1

- [ ] Home-Server: legitime Quellen inventarisieren, dann UFW auf `default deny incoming`
- [ ] Log-Rotation für `/var/log/honeypot/cowrie.json` (Home) und Test der Cowrie-Rotation mit Vector
- [ ] Reboot-Test des Home-Servers (Receiver-Bind an Tailscale-IP)
- [ ] isolierter Test von Home-UFW und `permit_origin`
- [ ] automatische Sicherheitsupdates auf dem VPS verifizieren
- [ ] Aufbewahrung und Größe von TTY-Logs und Cowrie-Downloads begrenzen
- [ ] Sender-Testdatei `/var/log/honeypot-sender/` entfernen

## G. Optionale Erweiterungen

| Erweiterung | Nutzen |
|---|---|
| Vector-natives Protokoll (Vector → Vector) mit Acknowledgements | stärkere Zustellsemantik als der best-effort `socket`-Sink |
| TLS innerhalb des Tailscale-Tunnels | Defense-in-Depth auf Anwendungsebene |
| GeoIP-, ASN- und Länder-Anreicherung | Herkunftsanalyse der Kampagnen |
| Threat-Intelligence-Anreicherung | Abgleich von IPs und Hashes mit Reputationsquellen |
| Automatisierte IoC-Extraktion und Reporting | IPs, URLs, Hashes, HASSH je Kampagne |
| Weitere Honeypot-Protokolle | z. B. Telnet in Cowrie |
| Sicherer Umgang mit Samples | nur SHA-256, Metadaten, Reputation per Hash; Analyse ausschließlich isoliert – **niemals Ausführung von Malware** auf dem VPS oder im Heimnetz |
