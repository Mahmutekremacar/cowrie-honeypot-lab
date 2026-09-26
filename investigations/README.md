# Investigations

> **Status: Phase 2 – vier Untersuchungen abgeschlossen (Datenbasis 23.–26.09.2026).** Kampagnen-Übersicht: [`../docs/attack-statistics.md`](../docs/attack-statistics.md).

## Ziel

Aus realer Honeypot-Telemetrie nachvollziehbare, professionelle Analyseberichte erstellen – vom einzelnen Alert zur rekonstruierten Session mit IoCs, ATT&CK-Mapping und Bewertung der Detection Coverage.

## Datenquellen

| Quelle | Inhalt |
|---|---|
| Wazuh (`wazuh-alerts-*`, Filter `rule.groups:cowrie`) | Alerts 110211–110219 mit `data.*`-Feldern |
| `/var/log/honeypot/cowrie.json` (Home) | vollständige Rohereignisse aller Event-Typen, inkl. solcher ohne Alert (z. B. `cowrie.client.version`, `cowrie.client.kex`, `cowrie.session.closed`) |
| Cowrie-TTY-Logs (VPS, `var/lib/cowrie/tty/`) | Wiedergabe der Terminal-Session (`playlog`) – nur lokal auswerten |

## Vorgehen

1. **Auswahl:** Session über das Dashboard identifizieren (z. B. Top Source IP, auffälliges Kommando).
2. **Abgrenzung:** alle Events mit derselben `data.session` bzw. `src_ip` im Zeitfenster sammeln.
3. **Timeline:** `session.connect` → `client.version`/`client.kex` → Login → Kommandos → `session.closed`.
4. **Einordnung:** Automatisiert (Bot) oder interaktiv? Hinweise: Timing zwischen Kommandos, Client-Version, HASSH, identische Sequenzen über mehrere Quellen.
5. **IoCs:** anonymisierte IP, Client-Version, HASSH, Kommandos, ggf. URLs (defanged, z. B. `hxxp://example[.]invalid`) und Hashes.
6. **ATT&CK:** beobachtete Aktivität → Technik (mit Begründung, keine Überinterpretation).
7. **Detection Coverage:** Welche Schritte wurden durch welche Regel erkannt? Was fehlte?
8. **Fazit und Maßnahmen:** Bewertung, Regelverbesserungen.

## Regeln für Berichte

- Keine realen IPs, Passwörter oder URLs im Klartext (siehe [`../SECURITY.md`](../SECURITY.md)).
- Beobachtung und Interpretation klar trennen („beobachtet" vs. „Hypothese").
- `cowrie.login.success` = von Cowrie akzeptierter Login in die **emulierte** Shell, kein Zugriff auf das echte System.

## Berichte

| ID | Kampagne | Titel | Kernbefund |
|---|---|---|---|
| [HP-001](HP-001.md) | K5 | GPU-Check, curl-Download und Perl-Ausführung | alle Downloads gescheitert (Egress-Sperre aktiv); neue Regel 110221 |
| [HP-002](HP-002.md) | K3 | Mehrstufiges Shell-Fingerprinting | verteilte Inventur mit Echtheitsprüfung der Shell; Falsch-Positive bei 110216 behoben |
| [HP-003](HP-003.md) | K6 | Dropper mit eingebettetem SSH-Private-Key | `scp`-Transfer mit eigenem Key, HTTPS-Fallback in `sh`; neue Regel 110224 |
| [HP-004](HP-004.md) | K8 | SFTP-Upload eines ELF-Binaries „sshd“ | Upload ohne Shell-Kommando, Binary inert gesichert |

## Anonymisierungsschema

`ATTACKER-IP-xx` (einzelne Quelle, Nummer = Kampagne), `ATTACKER-NET-A…` (/24-Netze), `STAGING-xx` (Payload-Server). URLs sind entschärft (`hxxp://`). SHA-256-Hashes und HASSH-Werte werden als IoCs veröffentlicht.
