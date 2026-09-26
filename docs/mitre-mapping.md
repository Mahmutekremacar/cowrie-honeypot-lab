# MITRE ATT&CK – beobachtete Techniken und Detection Coverage

**Grundlage:** reale Honeypot-Telemetrie vom 23.–26.09.2026 ([`attack-statistics.md`](attack-statistics.md)) und die Untersuchungen [HP-001](../investigations/HP-001.md) bis [HP-004](../investigations/HP-004.md).
**Regelwerk:** [`wazuh/rules/cowrie_rules.xml`](../wazuh/rules/cowrie_rules.xml) Version 2.

Dieses Mapping ordnet **beobachtetes Verhalten** Techniken zu, nicht nur Regeln. Einträge mit *(Hypothese)* beschreiben eine plausible Absicht, die aus den Daten nicht belegt ist.

Wichtig für die Einordnung: Alle Aktivitäten fanden in der **emulierten** Cowrie-Umgebung statt. „Ausführung“ heißt hier: Der Angreifer hat es *versucht*. Auf dem echten System lief nichts davon.

## 1. Matrix

| Taktik | Technik | Beobachtet in | Umfang | Wazuh-Regel (v2) | Coverage |
|---|---|---|---|---|---|
| Credential Access | **T1110.001** Password Guessing | alle Kampagnen | 15.498 Login-Versuche, 390 Benutzernamen, 1.928 Passwörter | 110212, 110213, **110219** (Korrelation) | ✔ |
| Execution | **T1059** / **T1059.004** Unix Shell | alle Kampagnen mit Kommandos | 16.845 Kommandozeilen | 110214 (+ Kind-Regeln) | ✔ |
| Discovery | **T1082** System Information Discovery | K1, K3, K4, K5, K6 | > 11.000 Sessions | **110226** | ✔ |
| Discovery | **T1033** System Owner/User Discovery | K3 (`last`), Einzelsessions (`whoami`) | 385+ | 110226 (nur `whoami`) | ◐ `last` fehlt |
| Command and Control | **T1105** Ingress Tool Transfer | K5 (curl), K6 (scp/wget/curl), K8 (SFTP) | 9 + 1 + 3 | 110215, **110221**, **110223**, **110224**, 110217 | ✔ |
| Command and Control | **T1090** Proxy | K7 (`direct-tcpip`) | 108 Anfragen | **110222** | ✔ |
| Defense Evasion | **T1222.002** Linux File/Directory Permissions Modification | K3, K6 | 1.155 Kommandos | **110225** | ✔ |
| Defense Evasion | **T1070.004** File Deletion | K3, K6 (`rm -rf` eigener Dateien) | 386 | – | ✘ Lücke |
| Defense Evasion | **T1027** Obfuscated Files or Information | K6 (hex-kodierter Marker) | 1 | – | ✘ (geringe Relevanz) |
| Defense Evasion | **T1036.005** Match Legitimate Name *(Hypothese)* | K8 (Upload „sshd“) | 3 | 110217 (nur Upload an sich) | ◐ |
| Defense Evasion / Discovery | **T1497.001** Sandbox Evasion: System Checks *(Hypothese)* | K3 (Shell-Verhaltenstest) | 385 | – | ✘ Lücke |
| Impact | **T1496** Resource Hijacking *(Hypothese)* | K5 (gezielte GPU-Suche) | 9 | – | nicht beobachtbar (Payload nie geladen) |

✔ abgedeckt · ◐ teilweise · ✘ nicht abgedeckt

## 2. Verteilung (vereinfacht, nach Sessions)

```text
Credential Access  T1110.001  ████████████████████████████████  ~15.500 Login-Versuche
Discovery          T1082      ███████████████████████           ~11.400 Sessions
Execution          T1059      ████████████████████████████████  ~16.800 Kommandos
Defense Evasion    T1222.002  ██                                ~1.150
Command & Control  T1090      ▏                                 108
Command & Control  T1105      ▏                                 13
```

Die Aktivität besteht fast nur aus **Credential Access, Discovery und Execution-Checks**. Echte Payload-Stufen (T1105) waren selten, und keine davon war erfolgreich.

## 3. Lücken und Backlog

| Lücke | Vorschlag | Priorität |
|---|---|---|
| T1070.004 Spurenbeseitigung | Kind-Regel auf `rm -rf` von zuvor geschriebenen Dateien bzw. in `/tmp`, `/var/tmp`, `/dev/shm` | mittel |
| T1497.001 Shell-Fingerprinting | Signaturregel auf K3-Marker (`===SHELL_BEHAVIOR===`) zur Kampagnen-Zuordnung | niedrig (kampagnenspezifisch) |
| T1033 `last` | Discovery-Regel 110226 um `\blast\b` erweitern (auf False Positives prüfen) | niedrig |
| T1036.005 Tarnnamen | Regel auf `file_upload` mit `filename` wie `sshd`, `systemd`, `kworker` → Level 12 | mittel |
| Kampagnen-Korrelation | gleiche Quelle, mehrere parallele Sessions mit identischem Kommando (K5-Muster) | niedrig |

## 4. Nicht beobachtet (trotz Regel)

- Erfolgreicher Netz-Download (`cowrie.session.file_download` **mit** URL, Regel 110216): 0 Treffer. Das ist erwartbar, weil die Egress-Sperre Cowrie jede neue ausgehende Verbindung verbietet.
- Persistenz (Cronjobs, `authorized_keys`, Services): in diesem Zeitraum nicht beobachtet.
