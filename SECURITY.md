# Sicherheit, Veröffentlichung und Anonymisierung

Dieses Repository dokumentiert einen **produktiv betriebenen** Honeypot. Deshalb gelten für alle Inhalte die folgenden Regeln.

## 1. Was niemals veröffentlicht wird

- Private SSH-Keys, Passphrasen, Host-Key-Fingerprints
- Tailscale-Auth-Keys, Tailnet-Namen, API-Tokens
- Wazuh-Credentials (Dashboard, API, Indexer, Agent-Keys)
- Eigene öffentliche IP-Adressen (VPS, Heimanschluss, IPv4 und IPv6)
- Interne Adressen (Tailscale-IPs, LAN-IPs) und Benutzernamen der eigenen Systeme
- Reale Passwortversuche von Angreifern
- Von Angreifern verwendete URLs, Download-Quellen und erfasste Dateien (Samples)
- Sensor-UUIDs und Pfade zu TTY-Aufzeichnungen

## 2. Platzhalter

| Platzhalter | Ersetzt |
|---|---|
| `<HONEYPOT_PUBLIC_IP>` | öffentliche IPv4/IPv6 des VPS |
| `<HONEYPOT_TAILSCALE_IP>` | Tailscale-IP des VPS |
| `<WAZUH_TAILSCALE_IP>` | Tailscale-IP des Home-SIEM |
| `<ADMIN_TAILSCALE_IP>` | Tailscale-IP der Admin-Workstation |
| `<ADMIN_PUBLIC_IP>` | öffentliche IP des eigenen Anschlusses (z. B. bei Eigentests) |
| `<ATTACKER_IP>` / `ATTACKER-IP-01`, `-02`, … | reale externe Quellen (konsistent pro Quelle nummeriert) |
| `<REDACTED_PASSWORD>` | Passwörter / Passwortversuche |
| `<SENSOR_UUID>`, `<TTYLOG_SHA256>` | Sensor- und Aufzeichnungskennungen |
| `203.0.113.0/24` | Dokumentationsnetz (RFC 5737) für synthetische Beispiele |

## 3. Screenshots

- Rohaufnahmen nur lokal in `screenshots/raw/` (per `.gitignore` ausgeschlossen).
- Vor dem Commit: IPs, Passwörter, Tailnet-Namen, Hostnamen, Benutzernamen, Zeitstempel mit Personenbezug schwärzen – **deckend**, nicht per Weichzeichner.
- Das Panel „Top Passwords" wird nur geschwärzt oder gar nicht veröffentlicht.
- Metadaten (EXIF) entfernen.

## 4. Umgang mit Angreiferdaten

- Daten werden ausschließlich defensiv ausgewertet.
- IP-Adressen gelten als personenbezogene Daten im Sinne der DSGVO und werden in öffentlichen Berichten anonymisiert.
- Erfasste Dateien werden nie ausgeführt und nie in dieses Repository gelegt; veröffentlicht werden höchstens SHA-256, Größe, Dateityp und Zeitpunkt.
- Keine aktiven Gegenmaßnahmen, keine Scans, keine Kontaktaufnahme mit Quellen.

## 5. Sicherheitsprobleme melden

Wer in diesem Repository versehentlich veröffentlichte sensible Daten findet, meldet dies bitte vertraulich an den Repository-Owner (Kontakt über das GitHub-Profil), statt ein öffentliches Issue zu eröffnen.
