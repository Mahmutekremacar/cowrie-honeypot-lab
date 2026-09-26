# Hardening – Entscheidungen und Begründungen

Dieses Dokument erklärt **warum** jede Härtungsmaßnahme so umgesetzt wurde. Die Konfigurationsdateien liegen unter [`configs/`](../configs/).

## 1. Echter SSH-Dienst (Administration)

| Entscheidung | Begründung |
|---|---|
| **Dedizierter Ed25519-Key** mit Passphrase (`-a 100`) statt Wiederverwendung eines vorhandenen RSA-Keys | Das System ist absichtlich Angriffen ausgesetzt; ein eigener Key begrenzt den Schaden bei Kompromittierung und ist gezielt widerrufbar. |
| Reihenfolge **Key hinterlegen → Key-only testen → Passwort-Login deaktivieren** | Das OVH-Image erlaubte anfangs `passwordauthentication yes` und `permitrootlogin without-password`. Ein Deaktivieren vor dem Key-Test hätte zum Lockout führen können. |
| Drop-In `sshd_config.d/00-honeypot-hardening.conf` statt Editieren von `sshd_config` | Updates von `sshd_config` bleiben konfliktfrei; `00-` sorgt dafür, dass diese Werte vor anderen Drop-Ins (z. B. Cloud-init) gelesen werden – OpenSSH übernimmt bei diesen Optionen den ersten Wert. |
| `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no` | Nur Public-Key-Authentisierung für einen normalen Admin-User mit sudo. |
| Port **22222** statt 22 | Port 22 gehört dem Honeypot. |
| Verschiebung über **`ssh.socket`-Drop-In** | Ubuntu 24.04 nutzt Socket Activation; `ssh.socket` hält den Port. |
| Listener `0.0.0.0:22222` **und** `[::]:22222` | Die Basis-Unit setzt `BindIPv6Only=ipv6-only`; ohne expliziten IPv4-Listener sind IPv4-Verbindungen (Tailscale-IPv4) nicht möglich. |
| Bind auf alle Adressen + UFW statt `ListenAddress <Tailscale-IP>` | Ein Bind an die Tailscale-IP kann beim Boot scheitern, wenn ssh.socket vor tailscaled startet → Admin-Zugang wäre verloren. UFW erzwingt die Einschränkung zuverlässig. |
| UFW: 22222 nur `in on tailscale0` **von der Admin-Tailscale-IP** | Weder das Internet noch andere Tailnet-Geräte (auch nicht der Home-Server) können den echten SSH erreichen. |

## 2. Firewall VPS (UFW)

| Entscheidung | Begründung |
|---|---|
| `default deny incoming` | Nur explizit benötigte Dienste sind erreichbar. |
| `default allow outgoing` + **prozessbezogene** Einschränkung | Ein pauschales `deny outgoing` hätte DNS, apt, Tailscale-Koordination/DERP und Vector gefährdet. Die eigentliche Gefahr ist der Honeypot-Prozess – genau dieser wird eingeschränkt. |
| Temporäre 22/tcp-Regel mit Kommentar `TEMP …` | Nachvollziehbarkeit: Die Regel wurde nach dem Umzug durch eine Regel mit korrektem Zweck (`Public Cowrie SSH honeypot`) ersetzt. |

## 3. Process-Level Egress Containment

**Ziel:** Der Linux-User `cowrie` darf auf eingehende Sitzungen antworten, aber selbst **nichts Neues** initiieren.

```text
ufw-before-output / ufw6-before-output
  1. RELATED,ESTABLISHED -> ACCEPT
  2. owner --uid-owner 1001 -> REJECT
  3. -o lo -> ACCEPT
  4. ufw-user-output
```

| Detail | Begründung |
|---|---|
| Regel **nach** RELATED,ESTABLISHED | Sonst könnte Cowrie nicht einmal auf die SSH-Verbindung des Angreifers antworten. |
| Loopback-Allow **hinter** die Cowrie-Sperre verschoben | In der UFW-Standardreihenfolge steht `-o lo -j ACCEPT` vorn. Dann könnte Cowrie lokale Dienste (z. B. den echten SSH auf `127.0.0.1:22222`) erreichen – ein lokaler Pivot. |
| `REJECT` statt `DROP` | Sofortige, eindeutige Rückmeldung (`Connection refused`) – für Tests klarer, Timeouts im Honeypot-Prozess werden vermieden. |
| IPv4 **und** IPv6 | Der VPS hat eine öffentliche IPv6-Adresse; eine Sperre nur für IPv4 wäre umgehbar. |
| Idempotentes Einfügeskript mit Backup und Vorabprüfung | Kein Duplizieren von Regeln, sicheres Rollback. |

**Grenze:** Schützt gegen Angreifer im Kontext des `cowrie`-Users, **nicht** gegen einen vollständigen Root-Compromise.

## 4. Cowrie-Dienst

| Entscheidung | Begründung |
|---|---|
| **Nativ statt Docker** | Von Docker veröffentlichte Ports können UFW umgehen (Docker schreibt eigene iptables-Regeln). Die Sicherheitslogik dieses Projekts beruht auf UFW/iptables. |
| Dedizierter User ohne Passwort, eigenes Virtualenv unter `/opt/cowrie` | Isolation vom System-Python und vom Admin-User. |
| `twistd -n` direkt unter systemd | Saubere Supervision (Vordergrundprozess, Restart bei Fehler); `cowrie start -n` existiert in 3.0.15 nicht. |
| `NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `ProtectSystem=full` | Reduziert, was ein kompromittierter Cowrie-Prozess im Dateisystem und bei Rechteausweitung erreichen kann. |
| `AmbientCapabilities`/`CapabilityBoundingSet` = nur `CAP_NET_BIND_SERVICE` | Port 22 ohne Root und ohne globales `setcap` auf den Python-Interpreter; alle anderen Capabilities (inkl. `CAP_NET_ADMIN`) sind ausgeschlossen. |
| Minimale `cowrie.cfg`, Telnet deaktiviert | Nur benötigte Angriffsfläche; Defaults bleiben updatefähig. |

## 5. Dateirechte

| Entscheidung | Begründung |
|---|---|
| ACLs für den User `vector` (nur `x` auf Elternverzeichnisse, `r` auf die Logs) | Least Privilege statt `chmod 777` oder globaler Leserechte. TTY-Logs, Downloads und Konfiguration bleiben für Vector unzugänglich. |
| Default-ACL auf dem Log-Verzeichnis | Neu erzeugte Log-Dateien (z. B. nach Rotation) bleiben für Vector lesbar. |
| Test-Verzeichnis `root:vector 0750` (Sender-Vorabtest) | Der Admin-User `ubuntu` hatte bewusst keinen Zugriff („Permission denied" war erwünscht). |

## 6. Tailscale

| Entscheidung | Begründung |
|---|---|
| Default-Policy `* → *` **vor** dem Beitritt ersetzt | Verhindert ein Zeitfenster, in dem der Honeypot das gesamte Tailnet erreicht. |
| Tag-Identität `tag:honeypot` statt Benutzer-Identität | Tags ersetzen die Benutzeridentität des Geräts; die breite `autogroup:member`-Regel greift nicht. |
| Auth-Key: nicht wiederverwendbar, nicht ephemeral, vorab genehmigt, getaggt | Ein gestohlener Key ist nicht erneut nutzbar; das Gerät bleibt nach Neustarts bestehen. |
| Key-Eingabe per `read -rsp`, danach `unset` | Kein Secret in der Shell-History. |
| Policy-`tests` | Tailscale lehnt künftige Änderungen ab, die den Honeypot an sensible Ports lassen würden. |

## 7. Home-Server

| Entscheidung | Begründung |
|---|---|
| UFW aktiviert mit **global `allow incoming`** und gezieltem Allow/Deny-Paar für die Honeypot-IP | Der Server bedient bereits Wazuh-Agents (1514/1515), Dashboard (443), API (55000) und SSH. Ohne Inventarisierung legitimer Quellen hätte `default deny` das bestehende Lab unterbrechen können. Die Honeypot-Identität ist trotzdem vollständig eingeschränkt. Umstellung auf default-deny ist ein eigener Folgeschritt. |
| Vector-Receiver an Tailscale-IP gebunden, `permit_origin` /32 | Zwei weitere unabhängige Schichten hinter Tailscale und UFW. |
| Frame-Limit 1 MiB, Rohdaten ohne Parsing | Kein unbegrenztes Puffern angreiferkontrollierter Zeilen; keine Parser-Logik im Receiver. |
| Kein Wazuh-Agent auf dem VPS | Der VPS erhält keinerlei Vertrauensbeziehung zum Manager. |

## 8. Offene Härtungspunkte

Siehe [README – Bekannte Einschränkungen](../README.md#bekannte-einschränkungen) und [`roadmap-phase2.md`](roadmap-phase2.md).
