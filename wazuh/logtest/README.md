# Regeltests mit `wazuh-logtest`

Jede Regel hat einen Testfall. Änderungen am Regelwerk werden **vor** dem Neustart des Wazuh-Managers geprüft, statt Regeln „blind" zu ändern.

## Schnellstart (Regelwerk v2)

Auf dem Home-SIEM, nachdem `cowrie_rules.xml` nach `/var/ossec/etc/rules/` kopiert wurde:

```bash
sudo bash wazuh/logtest/run-tests.sh
```

Das Skript schickt jedes Event aus [`test-events.tsv`](test-events.tsv) einzeln durch den Unit-Test-Modus von `wazuh-logtest` (`-U <rule_id>:<level>:json`) und meldet `PASS`/`FAIL`. Bei einem Fehlschlag zeigt es die tatsächlich ausgelöste Regel-ID. Melden **alle** Tests `FAIL` mit „kein Treffer“, lädt das Regelwerk meist gar nicht. Dann zuerst `sudo /var/ossec/bin/wazuh-analysisd -t` ausführen.

Erwartete Ausgabe:

```text
PASS  110211 (level 3)
…
PASS  110222 (level 6)
----
Bestanden: 15  Fehlgeschlagen: 0
```

| Test | Prüft |
|---|---|
| 110211–110213 | Session und Authentifizierung |
| 110214 | generisches Kommando (`echo xsec`) |
| 110226 / 110215 / 110223 / 110224 / 110225 | Reihenfolge der Kind-Regeln von 110214 (Discovery, wget/curl, Download-an-Shell, Private Key, chmod) |
| 110218 | nicht unterstütztes Kommando |
| 110216 / 110220 | Trennung echter Download (mit `url`) vs. Shell-Umleitung |
| 110221 | gescheiterter Download |
| 110217 | SFTP-Upload |
| 110222 | SSH-Tunnel-/Proxy-Anfrage |

Die Testevents sind **strukturell identisch mit realen Cowrie-Events** aus der Auswertung vom 23.–26.09.2026, aber synthetisch: Quell-IPs aus `203.0.113.0/24` (RFC 5737), URLs auf `example.invalid`, Schlüssel und Passwörter entfernt.

**Nicht enthalten:** die Korrelationsregel 110219 (`frequency`). Manuell testen: `wazuh-logtest` starten und 20 Zeilen `cowrie.login.success` mit derselben `src_ip` nacheinander einfügen. Ab dem 20. Event sollte 110219 auslösen.

**Ergebnis mit dem echten Regelwerk (Home-SIEM, Wazuh 4.14.7, 26.09.2026):**

```text
PASS  110211 (level 3)
PASS  110212 (level 4)
PASS  110213 (level 7)
PASS  110214 (level 5)
PASS  110226 (level 4)
PASS  110215 (level 8)
PASS  110223 (level 10)
PASS  110224 (level 10)
PASS  110225 (level 6)
PASS  110218 (level 4)
PASS  110220 (level 5)
PASS  110216 (level 10)
PASS  110221 (level 8)
PASS  110217 (level 10)
PASS  110222 (level 6)
----
Bestanden: 15  Fehlgeschlagen: 0
```

Die ersten beiden Läufe fanden zwei Fehler, die das Python-Modell nicht erkennen konnte: das statische Feld `url` und die XML-Entität `&amp;` (siehe [`docs/troubleshooting.md`](../../docs/troubleshooting.md#10-regelwerk-v2-lädt-nicht-field-url-is-static), Abschnitte 10 und 11). Vor jedem Neustart zusätzlich `sudo /var/ossec/bin/wazuh-analysisd -t` ausführen.

**Vorab-Validierung:** Vor der Übergabe wurde das Regelwerk mit einem Python-Modell der Wazuh-Auswertung (erste passende Kind-Regel gewinnt) gegen alle 15 Testfälle (15/15) und gegen die 128.810 realen Events simuliert. Die Trefferzahlen stehen im [README](../../README.md#detection-engineering). Das Modell ersetzt den Test mit dem echten Wazuh-Regelwerk **nicht**. Maßgeblich ist `run-tests.sh`.

---

## Verifizierte Ergebnisse aus Phase 1

### Pipeline-Testregel 110201

```text
**Phase 2: Completed decoding.
        name: 'json'
        eventid: 'lab.wazuh.test'
        sensor: 'honeypot-vps'
        src_ip: '<HONEYPOT_TAILSCALE_IP>'
        username: 'root'

**Phase 3: Completed filtering (rules).
        id: '110201'
        level: '5'
        description: 'Honeypot Wazuh ingestion test from <HONEYPOT_TAILSCALE_IP>'
        groups: '['honeypot', 'cowrie']'
**Alert to be generated.
```

Der erste Versuch mit den IDs `100200/100201` ergab `WARNING: (7612): Rule ID '100200' is duplicated`. Die IDs kollidierten mit einer älteren Lab-Regel, daher der eigene Bereich `1102xx`.

### Command-Regel 110214 (live)

```json
{"rule":{"level":5,"description":"Cowrie: Command executed by 127.0.0.1: uname -a","id":"110214",
 "mitre":{"id":["T1059"],"tactic":["Execution"],"technique":["Command and Scripting Interpreter"]},
 "groups":["honeypot","cowrie"]},
 "decoder":{"name":"json"},
 "data":{"eventid":"cowrie.command.input","input":"uname -a","sensor":"honeypot-vps","@source":"cowrie-honeypot"},
 "location":"/var/log/honeypot/cowrie.json"}
```

Mit Regelwerk v2 fällt genau dieses Kommando unter die spezifischere Discovery-Regel 110226.

### Live-Trefferzahlen Regelwerk v1 (23.–26.09.2026)

| Regel | Alerts |
|---|---|
| 110211 | 15.983 |
| 110212 | 46 |
| 110213 | 15.463 |
| 110214 | 16.854 |
| 110215 | 10 |
| 110216 | 772 (sämtlich Shell-Umleitungen → in v2 korrigiert) |
| 110217 | 3 |
| 110218 | 770 |
| 110219 | 0 |

Ermittelt aus den Wazuh-Alert-Archiven abzüglich der doppelt gezählten Tagesdatei (siehe [`docs/attack-statistics.md`](../../docs/attack-statistics.md#6-methodischer-hinweis-doppelzählung-bei-wazuh-archiven)).
