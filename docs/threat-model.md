# Threat Model

## 1. Schutzziel

> **Eine Kompromittierung des Honeypots darf nicht zu einer Kompromittierung des Heimnetzes führen – und der Honeypot darf nicht zur Angriffsplattform gegen Dritte werden.**

## 2. Annahmen

| # | Annahme |
|---|---|
| A1 | Der Honeypot-VPS ist **von Anfang an nicht vertrauenswürdig**. Jede Eingabe auf Port 22 ist angreiferkontrolliert. |
| A2 | Cowrie ist eine Emulation; Schwachstellen in Cowrie, Twisted oder Python können nicht ausgeschlossen werden. |
| A3 | Der Home-Server, die Admin-Workstation und die Tailscale-Control-Plane sind vertrauenswürdig. |
| A4 | Die vom Honeypot gelieferten Log-Inhalte sind **Daten, keine Wahrheit** – sie können manipuliert sein. |

## 3. Assets

| Asset | Warum schützenswert |
|---|---|
| Home-Wazuh (Manager, API, Dashboard, Indexer) | zentrales SIEM des Heimlabs |
| Weitere Tailnet-Geräte (Desktop, Smartphones, Server) | private Systeme |
| Echter SSH-Zugang des VPS | Kontrolle über den Sensor |
| Integrität/Verfügbarkeit der Telemetrie | Grundlage der Analyse |
| Reputation der VPS-IP / Provider-Vertrag | Missbrauch als Angriffsplattform verletzt AUP |

## 4. Bedrohungen und Gegenmaßnahmen

| ID | Bedrohung | Gegenmaßnahme(n) | Status |
|---|---|---|---|
| B1 | Angreifer gelangt vom Honeypot über das Tailnet an Home-Dienste (SSH, Dashboard, API, Agent-Ports) | Tag-Identität + Grant nur `tcp:6514`; Policy-Tests; Home-UFW-Deny; Receiver nur auf Tailscale-IP | verifiziert (`nc`-Tests) |
| B2 | Angreifer missbraucht Wazuh-Vertrauen (Agent-Enrollment, API) | kein Agent, keine Credentials auf dem VPS; Manager liest lokale Datei | umgesetzt |
| B3 | Angreifer erreicht den echten SSH-Dienst des VPS | echter SSH nur auf 22222, nur `tailscale0` von Admin-IP; nur Key-Auth, kein Root-Login | verifiziert |
| B4 | Honeypot-Prozess wird zur Angriffs-/Scan-Plattform oder lädt Payloads nach | UID-basiertes Egress-Blocking (IPv4 + IPv6) für `cowrie` | verifiziert (inkl. Reboot) |
| B5 | Lokaler Pivot aus dem Cowrie-Kontext (z. B. auf `127.0.0.1:22222`) | Egress-Regel vor Loopback-Allow; Test auf 22222 | verifiziert |
| B6 | Rechteausweitung aus Cowrie | unprivilegierter User; `NoNewPrivileges`, `ProtectSystem=full`, `ProtectHome`, `PrivateTmp`; Capability-Bounding-Set nur `CAP_NET_BIND_SERVICE` | konfiguriert, Dienst läuft |
| B7 | Übergroße/manipulierte Logzeilen belasten die Pipeline | `max_line_bytes` (Sender), `max_length` 1 MiB (Receiver); unverändertes Durchreichen ohne Parsing im Receiver | konfiguriert |
| B8 | Abhören/Manipulation der Logs im Transit | Tailscale/WireGuard-Verschlüsselung | Architektur |
| B9 | Verlust von Telemetrie bei Ausfall des Home-Servers | Disk-Buffer 512 MiB, `when_full: block` | konfiguriert (best-effort, keine Garantie) |
| B10 | Versehentliche Lockerung der Tailscale-Policy | Policy-Tests; Home-UFW als unabhängige zweite Schicht | konfiguriert |
| B11 | Veröffentlichung sensibler Daten (Credentials, IPs) im Portfolio | Anonymisierungsregeln, keine Passwörter in Alert-Beschreibungen | siehe `SECURITY.md` |

## 5. Restrisiken (bewusst akzeptiert bzw. offen)

| Restrisiko | Einordnung |
|---|---|
| **Vollständiger Root-Compromise des VPS** | Ein Angreifer mit Root kann lokale Firewall-Regeln entfernen und den VPS selbst missbrauchen. Die externen Grenzen (Tailscale-Policy, Home-UFW, Receiver) schützen das Heimnetz weiterhin, nicht aber Dritte vor dem VPS. Stärkeres Threat Model als Phase 1 abdeckt. |
| **Log-Injection / gefälschte Events** | Ein kompromittierter VPS kann beliebige Zeilen an 6514 senden. Wazuh behandelt sie als Daten; Alerts aus dieser Quelle sind entsprechend zu bewerten. Keine kryptografische Log-Integrität. |
| **Home-UFW default allow** | Die Honeypot-Identität ist eingeschränkt; andere Quellen sind auf dem Home-Server noch nicht per default-deny gefiltert (bewusst, um das bestehende Lab nicht zu beschädigen). |
| **Kein Anwendungs-TLS** | Transportsicherheit liegt vollständig bei WireGuard. |
| **Best-effort-Zustellung** | Datenverlust bei längeren Ausfällen oder vollem Puffer möglich. |
| **Provider-Ebene** | Kein zusätzlicher Netzwerk-Firewall-Layer beim Provider konfiguriert. |

## 6. Trust Boundaries

```text
┌───────────────────────────────┐
│ VERTRAUENSWÜRDIG              │
│ Home-Wazuh · Admin-Workstation│
│ übrige Tailnet-Geräte         │
└──────────────▲────────────────┘
               │  TRUST BOUNDARY
               │  nur TCP/6514, nur vom Honeypot initiiert
┌──────────────┴────────────────┐
│ NICHT VERTRAUENSWÜRDIG        │
│ OVH-VPS · Cowrie · Eingaben,  │
│ Sessions, Dateien der Angreifer│
└──────────────▲────────────────┘
               │  TCP/22
          ÖFFENTLICHES INTERNET
```
