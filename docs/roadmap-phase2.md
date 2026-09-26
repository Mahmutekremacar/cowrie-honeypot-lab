# Phase 2 – Detection Engineering, Threat Analysis und SOC Dashboarding

> **Status: geplant bzw. teilweise begonnen.** Nichts in diesem Dokument ist als abgeschlossen zu verstehen, sofern es nicht ausdrücklich als „vorhanden" markiert ist.

## A. Wazuh-Dashboard „Cowrie Honeypot SOC"

**Vorhanden (Ende Phase 1):** Total Connections · Successful Cowrie Logins · Commands Observed · Connections Over Time · Top Source IPs · Top Usernames · Top Passwords · Top Commands

**Offen:**

- [ ] Unique Source IPs (Cardinality auf `data.src_ip`)
- [ ] Event Types (Terms auf `data.eventid`)
- [ ] Download Commands (`rule.id: 110215`)
- [ ] Files Downloaded (`rule.id: 110216`)
- [ ] Recent Attacker Activity (Saved Search mit Session-Spalten)
- [ ] MITRE ATT&CK Overview (`rule.mitre.id` / `rule.mitre.technique`)
- [ ] Session-basierte Investigation-Panels (Drilldown über `data.session`)
- [ ] Eigene Test-IPs und `127.0.0.1` aus Portfolio-Ansichten filtern
- [ ] Export der Saved Objects (NDJSON) nach `wazuh/dashboard/`

## B. Detection Engineering

- [ ] Regeln 110212, 110215, 110218, 110219 mit `wazuh-logtest` und realen Events verifizieren und belegen
- [ ] Payload-Download/Upload-Erkennung schärfen (wget/curl/tftp/ftpget, `chmod +x`, Ausführung aus `/tmp`); prüfen, welche Events Cowrie bei durch die Egress-Sperre fehlgeschlagenen Downloads erzeugt
- [ ] Erkennung verdächtiger Shell-Kommandos (Discovery, Persistenz, Miner-Indikatoren)
- [ ] Command-Sequenzen und Session-basierte Korrelation (z. B. Login → Discovery → Download innerhalb einer Session)
- [ ] Wiederholte Login-Versuche feiner abstufen (Schwellenwerte, Zeitfenster)
- [ ] False-Positive-/Noise-Reduktion (eigene Tests, dominierende Bot-Muster wie `echo xsec`)
- [ ] Severity-Tuning über alle Regeln

## C. Real Attacker Investigation

Eine oder mehrere reale Sessions end-to-end analysieren (Vorlage: [`../investigations/TEMPLATE.md`](../investigations/TEMPLATE.md)):

Source IP (anonymisiert) · Zeitpunkt · Username · Passwortversuch (geschwärzt) · Session-ID · ausgeführte Kommandos · Downloads · Session-Dauer · IoCs · MITRE-ATT&CK-Mapping · Detection Coverage · Analyst Conclusion

## D. MITRE ATT&CK Mapping

- [ ] Beobachtete Aktivität (nicht nur Regeln) systematisch Techniken zuordnen
- [ ] Coverage-Matrix: welche beobachteten Techniken werden durch welche Regel erkannt, welche nicht
- [ ] Optional: ATT&CK-Navigator-Layer exportieren

## E. Dashboard und Screenshots

Anonymisierte Screenshots (Regeln in [`../SECURITY.md`](../SECURITY.md)) von: Cowrie-Dashboard · Wazuh-Alerts · Custom Rules · MITRE-Mapping · öffentlichem Cowrie-Listener · Tailscale-only-Admin-SSH · Egress-Containment · Vector/Tailscale-Pipeline

## F. Härtung / offene Punkte aus Phase 1

- [ ] Home-Server: legitime Quellen inventarisieren, dann UFW auf `default deny incoming`
- [ ] Log-Rotation für `/var/log/honeypot/cowrie.json` (Home) und Test der Cowrie-Rotation mit Vector
- [ ] Reboot-Test des Home-Servers (Receiver-Bind an Tailscale-IP)
- [ ] Isolierter Test von Home-UFW und `permit_origin`
- [ ] Automatische Sicherheitsupdates auf dem VPS verifizieren
- [ ] Aufbewahrung/Größe von Cowrie-TTY-Logs und Downloads begrenzen
- [ ] Entfernen der Sender-Testdatei `/var/log/honeypot-sender/`

## G. Optionale Erweiterungen

| Erweiterung | Nutzen |
|---|---|
| Vector-natives Protokoll (Vector → Vector) mit Acknowledgements | stärkere Zustellsemantik als der best-effort `socket`-Sink |
| TLS innerhalb des Tailscale-Tunnels | Defense-in-Depth auf Anwendungsebene |
| Zusätzliche Alert-Korrelation | mehrstufige Angriffsketten erkennen |
| GeoIP-Visualisierung, ASN-/Länder-Anreicherung | Herkunftsanalyse |
| Threat-Intelligence-Anreicherung | Abgleich von IPs/Hashes mit Reputationsquellen |
| Automatisierte IoC-Extraktion | IPs, URLs, Hashes aus Sessions |
| Reporting | regelmäßige Zusammenfassungen |
| Weitere Honeypot-Protokolle | z. B. Telnet in Cowrie, weitere Sensoren |
| Sicherer Umgang mit erfassten Samples | nur SHA-256, Metadaten, ggf. externe Reputation; Analyse nur isoliert – **niemals Ausführung von Malware** auf dem VPS oder im Heimnetz |
