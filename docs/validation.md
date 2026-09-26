# Validierung – Testmatrix mit Nachweisen

Alle Ausgaben stammen aus dem tatsächlichen Projektverlauf; IP-Adressen und Hostnamen sind durch Platzhalter ersetzt.

**Nachweis-Stufen:**
`Ausgabe` = Terminal-/Log-Ausgabe liegt vor · `Bestätigt` = vom Betreiber als erfolgreich gemeldet, ohne Ausgabe · `Indirekt` = aus nachgelagerten Ergebnissen ableitbar

## 1. Segmentierung Honeypot → Home

**T01/T02 – vor Installation des Receivers** (auf dem VPS, Nachweis: Ausgabe)

```text
=== SHOULD BE BLOCKED ===
nc: connect to <WAZUH_TAILSCALE_IP> port 22 (tcp) timed out: Operation now in progress
nc: connect to <WAZUH_TAILSCALE_IP> port 443 (tcp) timed out: Operation now in progress
nc: connect to <WAZUH_TAILSCALE_IP> port 1514 (tcp) timed out: Operation now in progress
nc: connect to <WAZUH_TAILSCALE_IP> port 1515 (tcp) timed out: Operation now in progress
nc: connect to <WAZUH_TAILSCALE_IP> port 55000 (tcp) timed out: Operation now in progress
=== SHOULD BE ALLOWED BUT NOTHING LISTENS YET ===
nc: connect to <WAZUH_TAILSCALE_IP> port 6514 (tcp) failed: Connection refused
```

Interpretation: `timed out` = durch Policy/Firewall blockiert. `Connection refused` auf 6514 = Pfad durch Tailscale **und** Home-UFW erlaubt, nur noch kein Dienst.

**T03 – nach Installation des Receivers** (Nachweis: Ausgabe)

```text
Connection to <WAZUH_TAILSCALE_IP> 6514 port [tcp/syslog-tls] succeeded!
```

(`syslog-tls` ist nur der IANA-Name des Ports; es wird kein TLS verwendet.)

**T04 – Receiver-Bind** (Home, Nachweis: Ausgabe)

```text
LISTEN 0 128 <WAZUH_TAILSCALE_IP>:6514 0.0.0.0:* users:(("vector",pid=…,fd=9))
```

**Home-UFW aktiv** (Nachweis: Ausgabe)

```text
Status: active
Default: allow (incoming), allow (outgoing), disabled (routed)
[ 1] <WAZUH_TAILSCALE_IP> 6514/tcp on tailscale0 ALLOW IN  <HONEYPOT_TAILSCALE_IP>  # Honeypot log ingestion
[ 2] Anywhere on tailscale0                      DENY IN   <HONEYPOT_TAILSCALE_IP>  # Block honeypot from other home services
```

> Hinweis: Die `nc`-Tests prüfen das Gesamtsystem. Da Tailscale die Ports bereits blockiert, wurde die Home-UFW-Schicht nicht isoliert getestet.

## 2. Pipeline

| Test | Nachweis |
|---|---|
| **T05** Test-JSON per `nc` → `/var/log/honeypot/cowrie.json` | Ausgabe: beide Testzeilen (`lab.transport.test`, `lab.wazuh.test`) in der Datei |
| **T05** `wazuh-logtest` | Ausgabe: Phase 2 `name: 'json'` mit allen Feldern, Phase 3 `id: '110201'`, `**Alert to be generated.` |
| **T05** Live-Alert | Ausgabe: `alerts.json` mit `"id":"110201"`, `"location":"/var/log/honeypot/cowrie.json"`, `"@source":"cowrie-honeypot"` |
| **T06** Vector-Sender ohne `nc` | Ausgabe: Alert `110201` mit Nachricht `AUTOMATED VECTOR SENDER TEST` (`firedtimes: 2`) |
| **T07** echte Cowrie-Events am Home-Server | Ausgabe: `cowrie.command.input`, `cowrie.command.failed`, `cowrie.log.closed`, `cowrie.session.closed` in der Home-Datei |
| **T08** Cowrie-Kommandos → Wazuh | Ausgabe: Alerts `110214`, Level 5, `mitre.id: ["T1059"]`, `technique: ["Command and Scripting Interpreter"]` für `whoami`, `uname -a`, `pwd`, `exit` |

## 3. SSH-Trennung

**Listener nach `ssh.socket`-Korrektur** (Nachweis: Ausgabe)

```text
LISTEN 0 4096 0.0.0.0:22222 0.0.0.0:* users:(("sshd",…),("systemd",pid=1,…))
LISTEN 0 50   0.0.0.0:2222  0.0.0.0:* users:(("twistd",…))
LISTEN 0 4096    [::]:22222    [::]:* users:(("sshd",…),("systemd",pid=1,…))
```

| Test | Nachweis |
|---|---|
| **T09** Admin-SSH über Tailscale auf 22222 | Ausgabe: Login, `whoami` → `ubuntu`, Hostname des VPS |
| **T10** Admin-SSH über öffentliche IP auf 22222 scheitert | Bestätigt („everything worked") |
| **T11** öffentliche IP TCP/22 → Cowrie | Bestätigt; zusätzlich Wazuh-Alerts mit externer `src_ip` (T16) |

**Finale Listener** (Nachweis: Ausgabe)

```text
LISTEN 0 4096 0.0.0.0:22222 0.0.0.0:* users:(("sshd",…),("systemd",pid=1,…))
LISTEN 0 50   0.0.0.0:22    0.0.0.0:* users:(("twistd",…))
LISTEN 0 4096    [::]:22222    [::]:* users:(("sshd",…),("systemd",pid=1,…))
```

**Cowrie auf Port 22 als unprivilegierter Dienst** (Nachweis: Ausgabe)

```text
Drop-In: /etc/systemd/system/cowrie.service.d
         └─override.conf
Active: active (running)
… /opt/cowrie/cowrie-env/bin/twistd -n --umask=0022 --pidfile= --logger cowrie.python.logfile.stdoutLogger cowrie
… [-] CowrieSSHFactory starting on 22
… [cowrie.ssh.factory.CowrieSSHFactory#info] Ready to accept SSH connections
```

## 4. Egress Containment

**Aktive Regeln** (Nachweis: Ausgabe)

```text
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m owner --uid-owner 1001 -j REJECT --reject-with icmp-port-unreachable
-A ufw-before-output -o lo -j ACCEPT
-A ufw-before-output -j ufw-user-output

-A ufw6-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw6-before-output -m owner --uid-owner 1001 -j REJECT --reject-with icmp6-port-unreachable
-A ufw6-before-output -o lo -j ACCEPT
```

| Test | Befehl | Ergebnis |
|---|---|---|
| **T12** Cowrie → Internet | `sudo -u cowrie timeout 5 bash -c 'echo > /dev/tcp/1.1.1.1/80'` | `Connection refused` → `GOOD: Cowrie outbound blocked` |
| **T13** Cowrie → lokaler echter SSH | `sudo -u cowrie timeout 5 bash -c 'echo > /dev/tcp/127.0.0.1/22222'` | `Connection refused` → `GOOD: Cowrie cannot reach real SSH` |
| **T14** Admin → Internet | `curl -I --max-time 5 https://example.com` | `HTTP/2 200` |
| **T15** Vector → Home | `ss -tnp \| grep ':6514'` | `ESTAB <HONEYPOT_TAILSCALE_IP>:… → <WAZUH_TAILSCALE_IP>:6514 users:(("vector"…))` |
| Dienste | `systemctl is-active cowrie vector tailscaled` | `active` ×3 |

## 5. Live-Internet-Test

**T16** – externer Eigentest mit Fake-Credentials, Kommandos `whoami`, `id`, `uname -a`, `pwd`, `exit`: Wazuh-Alerts `110214` (Level 5, T1059) mit externer Quell-IP (`<ADMIN_PUBLIC_IP>`, nicht `127.0.0.1`). Parallel: unaufgeforderte externe Quelle `ATTACKER-IP-01` mit akzeptiertem Login und Kommando `echo xsec`, ebenfalls als `110214` erkannt.

## 6. Reboot- und Persistenztests

**T17 – Reboot vor dem SSH-Umzug** (Nachweis: Ausgabe): `active active active`; `0.0.0.0:2222` → twistd, `0.0.0.0:22`/`[::]:22` → sshd.

**T18 – Reboot nach Einführung der Egress-Regeln** (Nachweis: Ausgabe) – **fehlgeschlagen**:

```text
active
active
active
LISTEN 0 4096 0.0.0.0:22222 …  sshd
LISTEN 0 50   0.0.0.0:22    …  twistd
LISTEN 0 4096    [::]:22222 …  sshd
-A ufw-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw-before-output -m owner --uid-owner 1001 -j REJECT --reject-with icmp-port-unreachable
-A ufw6-before-output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
-A ufw6-before-output -m owner --uid-owner 1001 -j REJECT --reject-with icmp6-port-unreachable
SYN-SENT 0 1 <HONEYPOT_PUBLIC_IP>:44412 <WAZUH_TAILSCALE_IP>:6514 users:(("vector",…))
GOOD: containment survived reboot
```

Diagnose (Ausgabe): `tailscale ping` → pong in 20 ms; `nc … 6514` → succeeded; `ip route get <WAZUH_TAILSCALE_IP>` → `dev tailscale0 table 52 src <HONEYPOT_TAILSCALE_IP>`. → Boot-Race, Fix siehe [`troubleshooting.md`](troubleshooting.md#6-vectortailscale-boot-race).

**T19 – Acceptance-Test nach Fix und erneutem Reboot** (Nachweis: Ausgabe):

```text
active
active
active
<WAZUH_TAILSCALE_IP> dev tailscale0 table 52 src <HONEYPOT_TAILSCALE_IP> uid 1000
    cache
ESTAB 0 0 <HONEYPOT_TAILSCALE_IP>:46050 <WAZUH_TAILSCALE_IP>:6514 users:(("vector",…))
-A ufw-before-output -m owner --uid-owner 1001 -j REJECT --reject-with icmp-port-unreachable
GOOD
```

## 7. Nicht (oder nicht isoliert) getestet

- Home-UFW und `permit_origin` bei gelockerter Tailscale-Policy
- Regeln 110212, 110215–110219 (siehe [`../wazuh/logtest/README.md`](../wazuh/logtest/README.md))
- Verhalten des Disk-Buffers bei längerem Ausfall des Home-Servers
- Log-Rotation von `cowrie.json`
- Reboot des Home-Servers (Receiver-Bind an Tailscale-IP)
- Deaktivierter Passwort-Login mit explizitem Negativtest (`-o PubkeyAuthentication=no`) – nur über `sshd -T` belegt
