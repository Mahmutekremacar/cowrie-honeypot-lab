# Wazuh-Dashboard „Cowrie Honeypot SOC"

Datenquelle: Index-Pattern `wazuh-alerts-*` · Basisfilter: `rule.groups:cowrie`
Erstellt unter **Explore → Visualize** bzw. **Explore → Dashboards** (Wazuh 4.14.7).

> **Status:** In Phase 1 begonnen, 8 Panels vorhanden. Mit Regelwerk v2 müssen zwei Panels auf Regelgruppen umgestellt werden (s. u.); neue Panels sind in Arbeit.

## Wichtig nach dem Update auf Regelwerk v2

Kind-Regeln **ersetzen** den Alert ihrer Elternregel. Seit v2 laufen z. B. `uname`-Kommandos unter 110226 statt unter 110214. Panels, die mit `rule.id is 110214` filtern, zählen deshalb nur noch einen Teil der Kommandos.

| Panel | Filter bisher | Filter ab v2 |
|---|---|---|
| Cowrie - Commands Observed | `rule.id is 110214` | `rule.groups is cowrie_command` **und** `data.eventid is cowrie.command.input` |
| Cowrie - Top Commands | `rule.id is 110214` | wie oben |

Die Gruppen stehen erst nach dem Neustart des Managers und ggf. einem **Refresh field list** zur Verfügung. Alte Alerts behalten ihre alten Gruppen.

## Vorhandene Panels

| Panel | Typ | Filter | Aggregation |
|---|---|---|---|
| Cowrie - Total Connections | Metric | `rule.id is 110211` | Count |
| Cowrie - Successful Logins | Metric | `rule.id is 110213` | Count (von Cowrie akzeptierte Logins, **kein** Zugriff auf das echte System) |
| Cowrie - Commands Observed | Metric | s. o. | Count |
| Cowrie - Connections Over Time | Line | `rule.id is 110211` | Y: Count · X: Date Histogram auf `timestamp` |
| Cowrie - Top Source IPs | Horizontal Bar | `rule.id is 110211` | Terms `data.src_ip`, Size 10 |
| Cowrie - Top Usernames | Horizontal Bar | `rule.id is 110213` | Terms `data.username`, Size 10 |
| Cowrie - Top Passwords | Horizontal Bar | `rule.id is 110213` | Terms `data.password`, Size 10 – **nur privat; in Screenshots schwärzen** |
| Cowrie - Top Commands | Horizontal Bar | s. o. | Terms `data.input`, Size 10 |

**Designentscheidung:** „Top Source IPs" zählt nur Verbindungs-Events (`110211`). Sonst würde eine Quelle, die 100 Kommandos ausführt, das Ranking dominieren.

## Geplante Panels

| Panel | Typ | Filter / Feld | Bezug |
|---|---|---|---|
| Unique Source IPs | Metric | `rule.id is 110211`, Cardinality `data.src_ip` | |
| Event Types | Horizontal Bar | `rule.groups is cowrie`, Terms `data.eventid` | |
| Payload-Aktivität | Metric ×3 | `rule.id is 110215` / `110221` / `110217` | HP-001, HP-004 |
| Blocked Downloads | Table | `rule.id is 110221`, Spalten `timestamp`, `data.src_ip`, `data.url` | HP-001 |
| Tunnel-/Proxy-Versuche | Horizontal Bar | `rule.id is 110222`, Terms `data.dst_port` | K7 |
| High-Severity-Kommandos | Table | `rule.level >= 8` und `rule.groups is cowrie_command` | HP-003 |
| MITRE ATT&CK Overview | Horizontal Bar | `rule.groups is cowrie`, Terms `rule.mitre.technique` | [`mitre-mapping.md`](../../docs/mitre-mapping.md) |
| Client-Fingerprints | Table | `data.eventid is cowrie.client.kex`* , Terms `data.hassh` | Kampagnen-Clustering |
| Recent Attacker Activity | Saved Search | Spalten `timestamp`, `data.src_ip`, `data.username`, `data.eventid`, `data.input`, `data.session`, `rule.level` | |
| Session-Drilldown | Saved Search | gefiltert auf `data.session` | |

\* `cowrie.client.kex` erzeugt keinen Alert (Basisregel 110210 ist `noalert`). Für dieses Panel braucht es entweder eine eigene Regel mit Level > 0 oder Wazuh-Archive (`archives.json`).

Zusätzlich: eigene Test-IPs und `127.0.0.1` per `is not`-Filter aus Portfolio-Ansichten ausschließen.

## Praktische Hinweise

- **Neue Felder/Gruppen fehlen in der Feldliste:** *Dashboard Management → Index Patterns → `wazuh-alerts-*` → Refresh field list*.
- **DQL-Fehler im Visualize-Editor:** `rule.id:110211` wurde in der Query-Leiste abgelehnt. Zuverlässig funktioniert **Add filter** bei **leerer** Query-Leiste.
- **Horizontal Bar:** Unter *Buckets* steht nur „X-axis" zur Auswahl. Das ist korrekt, die Kategorien erscheinen trotzdem auf der vertikalen Achse.
- **Date Histogram:** Bei 24 h Zeitraum skaliert OpenSearch das Intervall automatisch, z. B. auf 10 Minuten.

Ein Export der Saved Objects (*Dashboard Management → Saved objects → Export*, NDJSON) soll nach Fertigstellung hier abgelegt werden.
