# Troubleshooting

Alle hier beschriebenen Probleme sind im Projekt tatsächlich aufgetreten. Für jedes Problem: Symptom → Diagnose → Ursache → Lösung.

---

## 1. Cowrie startet nicht: `FileNotFoundError` beim Start

**Symptom**

```text
Starting cowrie: [twistd --umask=0022 --pidfile var/run/cowrie.pid --logger cowrie.python.logfile.logger cowrie]...
  File ".../cowrie/scripts/cowrie.py", line 180, in cowrie_start
    os.execvp(twisted_args[0], twisted_args)
FileNotFoundError: [Errno 2] No such file or directory
```

**Ursache:** Der Cowrie-Launcher ruft `twistd` über `execvp` auf und sucht es im `PATH`. Ohne aktiviertes Virtualenv liegt `/opt/cowrie/cowrie-env/bin` nicht im `PATH`. (Ein zweiter Versuch scheiterte zusätzlich daran, dass `source cowrie-env/bin/activate` im Home-Verzeichnis des Admin-Users statt in `/opt/cowrie` ausgeführt wurde.)

**Lösung:** Als User `cowrie` in `/opt/cowrie` wechseln, `source /opt/cowrie/cowrie-env/bin/activate`, prüfen mit `which twistd cowrie`, dann `cowrie start`. Im systemd-Service wird der `PATH` explizit gesetzt.

---

## 2. systemd-Restart-Schleife: `unrecognized arguments: -n`

**Symptom**

```text
cowrie.service: Main process exited, code=exited, status=2/INVALIDARGUMENT
cowrie[6681]: usage: cowrie [-h] {init,start,stop,force-stop,restart,status,shell,bash,sh} [args ...]
cowrie[6681]: cowrie: error: unrecognized arguments: -n
cowrie.service: Scheduled restart job, restart counter is at 15.
```

**Diagnose:** `journalctl -u cowrie -n 80 --no-pager -l` und identischer Aufruf manuell als User `cowrie` – gleiche Fehlermeldung. Damit war klar: kein Rechte- oder systemd-Problem, sondern ein CLI-Problem.

**Ursache:** `-n` (nicht daemonisieren) ist eine Option von `twistd`. Die Cowrie-CLI 3.0.15 akzeptiert sie nicht.

**Lösung:** systemd startet Twisted direkt im Vordergrund:

```ini
ExecStart=/opt/cowrie/cowrie-env/bin/twistd -n --umask=0022 --pidfile= --logger cowrie.python.logfile.stdoutLogger cowrie
```

Vorher `systemctl stop cowrie && systemctl reset-failed cowrie`, Befehl manuell testen, dann Unit ersetzen.

---

## 3. Admin-SSH auf 22222: `Connection refused`

**Symptom:** `ssh -p 22222 ubuntu@<HONEYPOT_TAILSCALE_IP>` → `Connection refused`.

**Diagnose**

```text
$ sudo systemctl show ssh.socket -p Listen
Listen=[::]:22222 (Stream)

$ sudo systemctl cat ssh.socket
[Socket]
ListenStream=0.0.0.0:22
ListenStream=[::]:22
BindIPv6Only=ipv6-only
…
# /etc/systemd/system/ssh.socket.d/honeypot-admin.conf
[Socket]
ListenStream=
ListenStream=22222
```

**Ursache:** `ListenStream=22222` ohne Adresse erzeugte nur einen IPv6-Socket `[::]:22222`. Wegen `BindIPv6Only=ipv6-only` aus der Basis-Unit nahm dieser keine IPv4-Verbindungen an – die Tailscale-Adresse des VPS ist IPv4.

**Lösung**

```ini
[Socket]
ListenStream=
ListenStream=0.0.0.0:22222
ListenStream=[::]:22222
```

Danach `nc -zv <HONEYPOT_TAILSCALE_IP> 22222` → succeeded, Login über Tailscale erfolgreich.

**Warum `ssh.socket` und nicht `sshd_config`?** Ubuntu 24.04 nutzt systemd Socket Activation. Der Listening-Socket gehört `ssh.socket` (sichtbar in `ss` als `users:(("sshd",…),("systemd",pid=1,…))`).

---

## 4. Vector 0.58: `unknown field 'decoding'`

**Symptom**

```text
x sources.honeypot_test: unknown field `decoding`, expected one of `include`, `exclude`, … `max_line_bytes`, … `encoding`, …
```

**Ursache:** Der `file`-Source liest bereits jede Zeile in das Feld `message`; ein `decoding`-Block existiert dort nicht (anders als beim `socket`-Source des Receivers).

**Lösung:** Block entfernt, stattdessen `max_line_bytes: 1048576`.

---

## 5. Wazuh: `Rule ID '100200' is duplicated`

**Symptom:** `wazuh-logtest` dekodierte korrekt (Phase 2), Phase 3 lieferte aber nicht die erwartete Regel; Warnung `(7612): Rule ID '100200' is duplicated. Only the first occurrence will be considered.`

**Diagnose:** `grep -RIn 'rule id="100200"' /var/ossec/etc/rules /var/ossec/ruleset/rules` → eine ältere Korrelationsregel (`level="10" frequency="5" timeframe="120"`) aus einem früheren Lab nutzte dieselbe ID.

**Lösung:** Bestehende Regel unangetastet lassen; eigener Bereich `1102xx` für dieses Projekt, vorher per `grep` auf Kollisionen geprüft.

---

## 6. Vector/Tailscale Boot-Race

**Symptom** nach Reboot:

```text
SYN-SENT 0 1 <HONEYPOT_PUBLIC_IP>:44412 <WAZUH_TAILSCALE_IP>:6514 users:(("vector",…))
```

Vorher stets: `ESTAB <HONEYPOT_TAILSCALE_IP>:… → <WAZUH_TAILSCALE_IP>:6514`.

**Diagnose:** Alle Netzwerk-Tests waren unmittelbar danach erfolgreich (`tailscale ping`, `nc … 6514`, `ip route get` → `dev tailscale0 table 52 src <HONEYPOT_TAILSCALE_IP>`). Laut Journal startete Vector unmittelbar nach dem Boot und nahm die Datei-Überwachung sofort wieder auf – ohne Fehlermeldung, da der Healthcheck bewusst deaktiviert ist.

**Ursache:** Vector baute seine Verbindung auf, bevor Tailscale seine Policy-Routen (Tabelle 52) installiert hatte. Das Ziel wurde über die Default-Route (öffentliches Interface, Quelle = Public-IP) angesprochen; der SYN blieb unbeantwortet. Ein einmal angelegter Socket wechselt nicht nachträglich das Interface. Da kein Handshake zustande kam, wurden keine Logdaten übertragen.

**Lösung:** Drop-In `vector.service.d/tailscale-readiness.conf`:

- `After=`/`Wants=network-online.target tailscaled.service` (nur Reihenfolge – reicht allein nicht, weil „tailscaled gestartet" ≠ „Route nutzbar"),
- `ExecStartPre`: bis zu 30 × 2 s prüfen, ob `ip route get <WAZUH_TAILSCALE_IP>` `dev tailscale0` liefert,
- `Restart=on-failure`, `RestartSec=5`.

Nach erneutem Reboot: `ESTAB <HONEYPOT_TAILSCALE_IP>:46050 → <WAZUH_TAILSCALE_IP>:6514`.

---

## 7. Befehle auf dem falschen Host

**Vorfall A:** Die Segmentierungstests (`nc … 22/443/1514/1515/55000`) wurden zunächst auf dem **Home-Server** ausgeführt – alle „succeeded", weil der Server seine eigene Tailscale-IP ansprach. Kein Fehler der Konfiguration, aber ein wertloser Test.

**Vorfall B:** `ufw delete allow 22/tcp; ufw allow 22/tcp …` (gedacht für den VPS) wurde auf dem **Home-Server** ausgeführt und legte dort eine öffentliche 22/tcp-Regel an. Sofort erkannt, per `ufw status numbered` / `ufw delete <n>` entfernt und verifiziert.

**Ursache:** Mehrere Terminals, uneindeutige Namen (Hostname `home`, Tailscale-Name eines anderen Geräts, zufälliger Provider-Hostname auf dem VPS).

**Lösung/Prävention:** Prompt vor jedem Befehl prüfen, eindeutige Host- und Tailscale-Namen, Hostname-Check im Testskript ([`scripts/segmentation-test.sh`](../scripts/segmentation-test.sh)).

---

## 8. Wazuh-Dashboard

| Symptom | Ursache | Lösung |
|---|---|---|
| `data.src_ip` usw. in Events sichtbar, aber nicht in der Feldliste | Feld-Cache des Index-Patterns `wazuh-alerts-*` veraltet | *Dashboard Management → Index Patterns → wazuh-alerts-\* → Refresh field list* |
| Fehlermeldung bei Query `rule.id:110211` im Visualize-Editor | Query-Parser des Editors lehnte die Eingabe ab | Query-Leiste leeren, **Add filter** `rule.id is 110211` |
| Filter gesetzt, Fehler blieb | alte Query stand noch zusätzlich in der Leiste | Query vollständig löschen – nicht Filter **und** Query gleichzeitig |
| Zeitreihe als horizontale Balken | falscher Visualisierungstyp (Horizontal Bar statt Line) | als **Line** neu anlegen |
| Horizontal Bar bietet unter Buckets nur „X-axis" | erwartetes Verhalten | X-axis mit Terms-Aggregation verwenden |
| Speichern-Button nicht gefunden | Icon ohne Beschriftung | Disketten-Symbol links neben der Suchleiste |

---

## 9. Kleinere Punkte

| Situation | Einordnung |
|---|---|
| `ls /var/log/honeypot-sender/test.json` → `Permission denied` als `ubuntu` | gewollt: Verzeichnis `root:vector 0750`; mit `sudo` prüfen, Rechte **nicht** lockern |
| `cp /etc/vector/vector.yaml …bak` → `No such file or directory` | Paket lieferte keine Default-Konfiguration; Backup entfällt, Datei neu anlegen |
| `systemctl edit` – Einfügen im Editor unpraktisch | Drop-In direkt per `tee` mit Heredoc anlegen, danach `systemctl daemon-reload` und `systemctl cat` prüfen |
| `nc` zeigt Port 6514 als `syslog-tls` | nur IANA-Dienstname; kein TLS im Einsatz |
| Zwei `rule 5402`-Alerts („Successful sudo to ROOT") beim Prüfen der Alerts | normales Verhalten: Wazuh überwacht den Home-Server selbst und erkennt die eigenen `sudo grep`-Befehle |

---

## 10. Regelwerk v2 lädt nicht: `Field 'url' is static`

**Symptom:** Alle 15 Regressionstests meldeten „kein Treffer“. Die Einzelprüfung zeigte die Ursache:

```text
$ sudo /var/ossec/bin/wazuh-analysisd -t
wazuh-analysisd: ERROR: Failure to read rule 110216. Field 'url' is static.
wazuh-analysisd: CRITICAL: (1220): Error loading the rules: 'etc/rules/cowrie_rules.xml'.
```

**Ursache:** Wazuh kennt statische Felder (u. a. `srcip`, `dstip`, `user`, `id`, `url`, `data`, `status`). Der JSON-Decoder legt ein JSON-Feld mit diesem Namen dort ab. Solche Felder dürfen in Regeln nicht mit `<field name="…">` abgefragt werden, sondern nur über das gleichnamige Element.

**Lösung:** In Regel 110216 `<field name="url" type="pcre2">\S</field>` durch `<url type="pcre2">\S</url>` ersetzt.

**Lessons Learned:** Vor jedem Neustart `wazuh-analysisd -t` ausführen. Eine fehlerhafte Regeldatei stört den laufenden Manager nicht, verhindert aber seinen nächsten Start. Das Python-Modell der Regelauswertung konnte diesen Fehler nicht finden, weil es Wazuhs Parser-Regeln nicht kennt. Deshalb ist der Test mit dem echten Regelwerk Pflicht.

---

## 11. Regel 110223 greift nicht: `&amp;` im Muster

**Symptom:** Nach der Korrektur aus Abschnitt 10 bestanden 14 von 15 Tests. Die Einzelprüfung des Testevents für 110223 (`(wget … || curl …) | sh -s ssh`) ergab stattdessen:

```text
**Phase 3: Completed filtering (rules).
        id: '110215'
        level: '8'
```

**Ursache:** Das PCRE2-Muster enthielt die Zeichenklasse `[^;&amp;]`, also die XML-Schreibweise für `&`. Wazuhs Regel-Parser übersetzt diese Entität offenbar nicht zurück. Die Klasse schloss damit auch die Buchstaben `a`, `m` und `p` aus. Weil fast jede URL ein `a` enthält, passte das Muster praktisch nie. Die spezifischere Kind-Regel fiel aus, und die allgemeinere 110215 griff.

**Lösung:** `&` als Hex-Escape schreiben: `[^;\x26]`. Danach: **15/15 bestanden**.

**Zusätzlich im Test-Harness korrigiert:** `wazuh-logtest` schreibt seine Auswertung auf **stderr**. Die Fehlerdiagnose in `run-tests.sh` hatte stderr verworfen und deshalb „kein Treffer“ statt `110215` angezeigt.

**Lessons Learned:** In Wazuh-Regeln keine XML-Entitäten in Mustern verwenden. Sonderzeichen wie `&`, `<`, `>` in PCRE2 als `\x26`, `\x3c`, `\x3e` schreiben.
