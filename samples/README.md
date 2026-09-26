# Beispiel-Ereignisse (bereinigt)

`sanitized-events.jsonl` enthält **echte Cowrie-Ereignisse aus den lokalen Tests** der Phase 1
(Verbindung von `127.0.0.1` auf den damaligen Testport `2222`, vor dem Wechsel auf Port 22).

Bereinigt wurden:

| Feld | Ersetzt durch | Grund |
|---|---|---|
| `password` / Teile von `message` | `<REDACTED_PASSWORD>` | eingegebene Test-Passwörter werden grundsätzlich nicht veröffentlicht |
| `uuid` | `<SENSOR_UUID>` | eindeutige Sensor-Kennung |
| `ttylog` / `shasum` | `<TTYLOG_SHA256>` | Verweis auf lokale TTY-Aufzeichnung |

Das Event `cowrie.client.kex` (enthält u. a. den HASSH-Fingerprint des eigenen Test-Clients) wurde weggelassen.

**Hinweis:** Die Beispiele stammen aus kontrollierten Eigen-Tests. Reale Internet-Telemetrie
(Angreifer-IPs, Credentials, URLs) wird in diesem Repository nur **aggregiert oder anonymisiert**
dargestellt – siehe [`../SECURITY.md`](../SECURITY.md).

Die Beispiele eignen sich zum Nachvollziehen der Regeln mit `wazuh-logtest`
(siehe [`../wazuh/logtest/README.md`](../wazuh/logtest/README.md)).
