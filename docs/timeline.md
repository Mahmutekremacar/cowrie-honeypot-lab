# Timeline und Status je Komponente

Uhrzeiten in MESZ (UTC+2); Log-Zeitstempel der Systeme sind UTC.
Legende: **Geplant** · **Getestet** · **Fehlgeschlagen** · **Korrigiert** · **Final verifiziert** · **Verworfen**

## 23.09.2026 – Phase 1

| Zeit | Schritt | Status |
|---|---|---|
| 17:59 | Projektplanung: Cowrie + Vector + Tailscale + Wazuh, VPS als untrusted | Geplant |
| 18:15 | Hetzner ohne verfügbare Kapazität → Wechsel zu OVH (kleiner VPS-Tarif); AUP geprüft (passiver Sensor ok, keine Angriffe/Scans) | Korrigiert |
| 19:34 | Bestandsaufnahme VPS: nur sshd auf 22, UFW inaktiv | Getestet |
| 19:41 | `sshd -T`: Passwort-Login aktiv, `permitrootlogin without-password` | Getestet |
| 20:04 | Dedizierter Ed25519-Key, Key-only-Login in zweiter Sitzung | Final verifiziert |
| 20:21 | SSH gehärtet, UFW aktiv (deny in / allow out, 22 temporär), Ubuntu 24.04.5 gepatcht, Tailscale 1.102.4 installiert (noch nicht verbunden) | Final verifiziert |
| 20:25–20:29 | Tailnet-Policy: `* → *` ersetzt durch Member-Grant + `tag:honeypot → wazuh-home:tcp:6514` + Tests | Final verifiziert |
| 20:36 | VPS mit getaggtem Auth-Key beigetreten (ohne Benutzer-Owner) | Final verifiziert |
| 20:49 | Home-UFW aktiviert (Allow 6514 / Deny Rest für Honeypot-IP); Tests versehentlich auf dem Home-Server ausgeführt | Fehlgeschlagen (Testfehler) |
| 20:53 | Segmentierungstest vom VPS: 22/443/1514/1515/55000 timeout, 6514 refused | Final verifiziert |
| 20:56 | Backup der Vector-Default-Config nicht möglich (existierte nicht) | Korrigiert |
| 20:59 | Home-Vector-Receiver validiert, läuft, Bind nur Tailscale-IP:6514 | Final verifiziert |
| 21:10 | Test-JSON per `nc` in `/var/log/honeypot/cowrie.json`; 6514 vom VPS erreichbar | Final verifiziert |
| 21:18 | Wazuh-Regeln 100200/100201 → ID-Kollision | Fehlgeschlagen |
| 21:23 | IDs 110200/110201 → `wazuh-logtest` Alert | Korrigiert |
| 21:45 | Live-Alert 110201 aus echter VPS-Übertragung | Final verifiziert |
| 21:54 | Vector-Sender (VPS, 0.58.0): `decoding` im file-Source ungültig | Fehlgeschlagen → Korrigiert |
| 21:56 | Automatischer Vector-Sender → Alert 110201 | Final verifiziert |
| — | Docker-basierte Cowrie-Installation | Verworfen (UFW-Bypass-Risiko) |
| 22:05 | `cowrie start` → `FileNotFoundError` (twistd nicht im PATH) | Fehlgeschlagen |
| 22:09 | Cowrie 3.0.15 mit aktiviertem venv auf 2222 gestartet | Korrigiert |
| 22:12 | Lokale SSH-Sessions: `root@web01`, Events `session.connect` … `command.input` | Getestet |
| 22:21 | ACLs für Vector, Sender auf echte `cowrie.json`; Events kommen am Home-Server an | Final verifiziert |
| 22:30 | `cowrie_rules.xml` (110210–110219); 110214 + T1059 feuern live | Final verifiziert (110214) |
| 22:40 | systemd mit `cowrie start -n` → Restart-Schleife | Fehlgeschlagen |
| 22:45 | systemd mit `twistd -n … cowrie` | Korrigiert / Final verifiziert |
| 22:47 | Reboot-Test 1: cowrie/vector/tailscaled aktiv | Final verifiziert |
| — | Variante `ListenAddress <Tailscale-IP>` in `sshd_config` | Verworfen (Boot-Order-Risiko, Socket Activation) |
| 22:52 | `ssh.socket`-Drop-In nur `ListenStream=22222` → nur IPv6 → Connection refused | Fehlgeschlagen |
| 22:56 | Explizit `0.0.0.0:22222` + `[::]:22222`; Admin-SSH über Tailscale funktioniert | Korrigiert / Final verifiziert |
| 23:02 | Capability-Drop-In, Cowrie auf `0.0.0.0:22` | Final verifiziert |
| 23:05 | UFW-Befehl versehentlich auf Home-Server → Regel entfernt | Fehlgeschlagen → Korrigiert |
| 23:10 | VPS-UFW bereinigt (22 = Cowrie, 22222 nur Tailscale/Admin-IP); öffentliches 22222 scheitert | Final verifiziert (bestätigt) |
| 23:14 | Erste externe Verbindungen auf Cowrie:22 sichtbar | Beobachtet |
| 23:21–23:24 | UID-1001-Egress-Sperre IPv4/IPv6; Tests Internet/localhost/Admin/Vector | Final verifiziert |
| ~23:27 | Externer Eigentest + reale Quelle (`echo xsec`) in Wazuh als 110214 | Final verifiziert |
| 23:29 | Reboot-Test 2: Vector `SYN-SENT` über Public-IP | Fehlgeschlagen |
| 23:30–23:35 | Readiness-Drop-In; Reboot-Test 3: alles grün | Korrigiert / Final verifiziert |

## 24.–26.09.2026 – Phase 2

| Zeit | Schritt | Status |
|---|---|---|
| 24.09. 00:00 | Discover: Cowrie-Felder fehlten in der Feldliste → Refresh field list | Korrigiert |
| 24.09. 00:07–00:55 | Dashboard „Cowrie Honeypot SOC“: 3 KPIs, Connections Over Time, Top Source IPs/Usernames/Passwords/Commands | Teilweise umgesetzt |
| 26.09. | Rohdaten (128.810 Events) und Alert-Archive exportiert; Regelzählung zunächst durch doppelt gezählte Tagesdatei verfälscht | Korrigiert |
| 26.09. | Auswertung: 15.967 Verbindungen, 251 Quellen, Kampagnen K1–K8 | Final verifiziert |
| 26.09. | Befund: 110216 zählte 772 Shell-Umleitungen als Downloads; gescheiterte Downloads ohne Alert; 110219 wirkungslos | Fehlgeschlagen (Regelwerk v1) |
| 26.09. | Regelwerk v2 (110216/110219 korrigiert, 110220–110226 neu), Simulation gegen Rohdaten, 15 Testfälle | Getestet (Modell) |
| 26.09. | Untersuchungen HP-001 bis HP-004, ATT&CK-Mapping, Statistik | Final verifiziert |
| 26.09. | Test mit echtem Wazuh: Regelwerk lädt nicht (`Field 'url' is static`) | Fehlgeschlagen → Korrigiert |
| 26.09. | 14/15: 110223 greift nicht (XML-Entität `&amp;` im Muster) | Fehlgeschlagen → Korrigiert |
| 26.09. | 15/15 bestanden, `wazuh-analysisd -t` fehlerfrei, Manager mit v2 neu gestartet | Final verifiziert |
| — | Unique IPs, Event Types, Payload-/MITRE-Panels, Screenshots | Geplant |

## Endzustand je Komponente

| Komponente | Finaler Zustand |
|---|---|
| Echter SSH | ssh.socket `0.0.0.0:22222` + `[::]:22222`, Key-only, kein Root; UFW nur tailscale0 von Admin-IP |
| Cowrie | 3.0.15 nativ, User `cowrie` (UID 1001), systemd `twistd -n`, `0.0.0.0:22`, `CAP_NET_BIND_SERVICE` per Drop-In |
| Egress | `--uid-owner 1001 -j REJECT` nach RELATED,ESTABLISHED, vor Loopback, IPv4 + IPv6 |
| Vector-Sender | file → socket `<WAZUH_TAILSCALE_IP>:6514`, raw_message, Disk-Buffer 512 MiB, Readiness-Drop-In |
| Tailscale | `tag:honeypot`, Grant nur `tcp:6514` zu `wazuh-home`, Policy-Tests |
| Home-UFW | default allow; Honeypot-IP: Allow 6514, Deny Rest |
| Vector-Receiver | Bind `<WAZUH_TAILSCALE_IP>:6514`, `permit_origin` /32, → `/var/log/honeypot/cowrie.json` |
| Wazuh | `localfile` json + Label; Regeln 110200/110201 (Lab) und 110210–110226 (Cowrie, Regelwerk v2) |
