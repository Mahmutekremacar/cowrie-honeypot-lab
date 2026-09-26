# Investigations

> **Status: Phase 2 – noch keine abgeschlossene Untersuchung.** Dieser Ordner enthält die Methodik und eine Vorlage. Fertige Berichte werden als `HP-001.md`, `HP-002.md`, … ergänzt.

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

## Kandidaten aus Phase 1

| ID | Beschreibung | Status |
|---|---|---|
| HP-001 | Externe Quelle `ATTACKER-IP-01`: akzeptierter Login als `root`, Kommando `echo xsec`; eine der beiden aktivsten Quellen | geplant |
| HP-002 | Zweitaktivste Quelle `ATTACKER-IP-02` | geplant |
