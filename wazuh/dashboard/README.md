# Wazuh-Dashboard „Cowrie Honeypot SOC"

Datenquelle: Index-Pattern `wazuh-alerts-*` · Basisfilter: `rule.groups:cowrie`
Erstellt unter **Explore → Visualize** bzw. **Explore → Dashboards** (Wazuh 4.14.7).

> **Status:** In Phase 1 **begonnen**, Fertigstellung ist Teil von **Phase 2**.

## Vorhandene Panels (Stand Ende Phase 1)

| Panel | Typ | Filter | Aggregation |
|---|---|---|---|
| Cowrie - Total Connections | Metric | `rule.id is 110211` | Count |
| Cowrie - Successful Logins | Metric | `rule.id is 110213` | Count (von Cowrie akzeptierte Logins, **kein** Zugriff auf das echte System) |
| Cowrie - Commands Observed | Metric | `rule.id is 110214` | Count |
| Cowrie - Connections Over Time | Line | `rule.id is 110211` | Y: Count · X: Date Histogram auf `timestamp` |
| Cowrie - Top Source IPs | Horizontal Bar | `rule.id is 110211` | Terms `data.src_ip`, Size 10, absteigend nach Count |
| Cowrie - Top Usernames | Horizontal Bar | `rule.id is 110213` | Terms `data.username`, Size 10 |
| Cowrie - Top Passwords | Horizontal Bar | `rule.id is 110213` | Terms `data.password`, Size 10 – **nur privat; in Screenshots schwärzen** |
| Cowrie - Top Commands | Horizontal Bar | `rule.id is 110214` | Terms `data.input`, Size 10 |

**Designentscheidung:** „Top Source IPs" zählt nur Verbindungs-Events (`110211`), nicht alle Cowrie-Events.
Sonst würde eine Quelle, die 100 Kommandos ausführt, das Ranking künstlich dominieren.

## Geplante Panels (Phase 2)

| Panel | Typ | Filter / Feld |
|---|---|---|
| Unique Source IPs | Metric | `rule.id is 110211`, Cardinality auf `data.src_ip` |
| Event Types | Horizontal Bar | `data.sensor is honeypot-vps`, Terms `data.eventid` |
| Download Commands | Metric | `rule.id is 110215` |
| Files Downloaded | Metric | `rule.id is 110216` |
| Recent Attacker Activity | Saved Search | Spalten `timestamp`, `data.src_ip`, `data.username`, `data.eventid`, `data.input`, `data.session`, `rule.level` |
| MITRE ATT&CK Overview | Bar / Table | Terms `rule.mitre.id` bzw. `rule.mitre.technique` |
| Session-Drilldown | Saved Search / Table | gefiltert auf `data.session` |

Zusätzlich geplant: eigene Test-IPs und `127.0.0.1` per `is not`-Filter aus den Portfolio-Ansichten ausschließen.

## Praktische Hinweise (aus dem Aufbau)

- **Neue Felder erscheinen nicht in der Feldliste:** Die Werte waren in den Events sichtbar, aber nicht auswählbar.
  Ursache: veralteter Feld-Cache des Index-Patterns → *Dashboard Management → Index Patterns → `wazuh-alerts-*` → Refresh field list*.
- **DQL-Fehler im Visualize-Editor:** Die Eingabe `rule.id:110211` in der Query-Leiste wurde dort abgelehnt.
  Zuverlässig funktionierte **Add filter** (`rule.id is 110211`) bei **leerer** Query-Leiste.
- **Horizontal Bar:** Unter *Buckets* steht nur „X-axis" zur Auswahl – das ist korrekt, die Kategorien werden trotzdem auf der vertikalen Achse dargestellt.
- **Date Histogram:** Auch bei Minimum-Intervall „Minute" skaliert OpenSearch bei 24 h Zeitraum automatisch (z. B. auf 10 Minuten).

Ein Export der gespeicherten Objekte (*Dashboard Management → Saved objects → Export*, NDJSON) soll in Phase 2 hier abgelegt werden.
