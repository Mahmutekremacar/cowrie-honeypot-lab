# Installation (reproduzierbar, finaler Stand)

Diese Anleitung enthält **nur die final funktionierenden Schritte** in der Reihenfolge, in der sie sicher umzusetzen sind.
Fehlgeschlagene Varianten: [`troubleshooting.md`](troubleshooting.md).

> **Grundregel für Remote-Arbeit:** Bei jeder Änderung an SSH oder Firewall die bestehende Sitzung offen lassen und in einer **zweiten** Sitzung testen. Vor jedem Befehl prüfen, auf **welchem Host** der Prompt steht.

Platzhalter:

| Platzhalter | Bedeutung |
|---|---|
| `<HONEYPOT_PUBLIC_IP>` | öffentliche IPv4 des VPS |
| `<HONEYPOT_TAILSCALE_IP>` | Tailscale-IP des VPS |
| `<WAZUH_TAILSCALE_IP>` | Tailscale-IP des Home-SIEM-Servers |
| `<ADMIN_TAILSCALE_IP>` | Tailscale-IP der Admin-Workstation |

---

## Schritt 1 – Bestandsaufnahme (beide Systeme)

```bash
hostnamectl; cat /etc/os-release; ip -br addr
sudo ss -tulpn
sudo ufw status verbose
sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|pubkeyauthentication'
```

Home-Server zusätzlich: `tailscale status`, `tailscale ip -4`, `systemctl is-active wazuh-manager`.

## Schritt 2 – Dedizierter Admin-Key (Admin-Workstation, PowerShell)

```powershell
ssh-keygen -t ed25519 -a 100 -f "$env:USERPROFILE\.ssh\id_ed25519_honeypot" -C "honeypot-vps-admin"
Get-Content "$env:USERPROFILE\.ssh\id_ed25519_honeypot.pub" | ssh ubuntu@<HONEYPOT_PUBLIC_IP> "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys"
```

Auf dem VPS: `chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys`.
Key-only-Login in **neuer** Sitzung testen:

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519_honeypot" -o IdentitiesOnly=yes `
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no ubuntu@<HONEYPOT_PUBLIC_IP>
```

## Schritt 3 – SSH härten, UFW, Patches (VPS)

```bash
sudo tee /etc/ssh/sshd_config.d/00-honeypot-hardening.conf >/dev/null < configs/ssh/00-honeypot-hardening.conf
sudo sshd -t && sudo sshd -T | grep -E 'permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication'
sudo systemctl reload ssh

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'TEMP real SSH - remove after Tailscale admin access'
sudo ufw enable

sudo apt update && sudo apt full-upgrade -y && sudo apt autoremove -y   # kein do-release-upgrade
sudo timedatectl set-timezone UTC
```

## Schritt 4 – Tailscale installieren, Policy anpassen, getaggt beitreten

```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.noarmor.gpg | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
curl -fsSL https://pkgs.tailscale.com/stable/ubuntu/noble.tailscale-keyring.list | sudo tee /etc/apt/sources.list.d/tailscale.list >/dev/null
sudo apt update && sudo apt install -y tailscale
```

**Noch nicht `tailscale up`!** Zuerst in der Tailscale-Admin-Konsole die Policy aus [`configs/tailscale/policy.hujson`](../configs/tailscale/policy.hujson) speichern (Tests müssen bestehen).
Dann Auth-Key erzeugen: *Reusable OFF, Ephemeral OFF, Pre-approved ON, Tag `tag:honeypot`*.

```bash
read -rsp "Tailscale auth key: " TSKEY; echo
sudo tailscale up --auth-key="$TSKEY" --hostname=honeypot-vps
unset TSKEY
tailscale ip -4
```

In der Machines-Übersicht prüfen: `honeypot-vps` trägt `tag:honeypot` und **keinen** Benutzer als Owner.

## Schritt 5 – Home-Firewall (Home-Server)

Siehe [`configs/firewall/home/ufw-rules.sh`](../configs/firewall/home/ufw-rules.sh). Danach `sudo ufw status numbered`: die 6514-Allow-Regel muss **vor** der Deny-Regel stehen.

Segmentierung **vom VPS aus** prüfen ([`scripts/segmentation-test.sh`](../scripts/segmentation-test.sh)) – erwartet: 22/443/1514/1515/55000 `timed out`, 6514 `Connection refused` (noch kein Receiver).

## Schritt 6 – Vector-Receiver (Home-Server)

```bash
bash -c "$(curl -L https://setup.vector.dev)"
sudo apt update && sudo apt install -y vector
sudo install -d -o vector -g vector -m 0755 /var/log/honeypot
sudo mkdir -p /etc/vector
sudo cp configs/vector/vector-receiver.yaml /etc/vector/vector.yaml   # Platzhalter ersetzen
sudo vector validate /etc/vector/vector.yaml
sudo systemctl enable --now vector
sudo ss -ltnp | grep 6514        # erwartet: <WAZUH_TAILSCALE_IP>:6514, NICHT 0.0.0.0:6514
```

Vom VPS: `nc -zvw3 <WAZUH_TAILSCALE_IP> 6514` → `succeeded`; Testzeile senden:

```bash
printf '%s\n' '{"eventid":"lab.transport.test","src_ip":"<HONEYPOT_TAILSCALE_IP>","sensor":"honeypot-vps","message":"transport test"}' \
  | nc -N <WAZUH_TAILSCALE_IP> 6514
```

## Schritt 7 – Wazuh-Ingestion und Pipeline-Regel (Home-Server)

```bash
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-before-honeypot
# Inhalt von wazuh/ossec-localfile.xml innerhalb von <ossec_config> einfügen
sudo cp /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak-honeypot
# Block aus wazuh/rules/lab_pipeline_rules.xml in local_rules.xml ergänzen
sudo grep -RInE 'rule id="1102(00|01)"' /var/ossec/etc/rules /var/ossec/ruleset/rules   # ID-Kollisionen ausschließen
sudo /var/ossec/bin/wazuh-logtest     # erwartet: id '110201', "**Alert to be generated."
sudo systemctl restart wazuh-manager
sudo grep '110201' /var/ossec/logs/alerts/alerts.json | tail -n 3
```

## Schritt 8 – Vector-Sender (VPS)

```bash
bash -c "$(curl -L https://setup.vector.dev)"
sudo apt update && sudo apt install -y vector
sudo systemctl stop vector
```

Optionaler Vorab-Test mit einer Testdatei (`/var/log/honeypot-sender/test.json`, `root:vector 0640`), danach die finale Konfiguration aus Schritt 10.

## Schritt 9 – Cowrie installieren (VPS, nativ)

```bash
sudo apt install -y python3-pip python3-venv libssl-dev libffi-dev build-essential libpython3-dev python3-minimal acl
sudo adduser --disabled-password --gecos "" cowrie
sudo install -d -o cowrie -g cowrie -m 0750 /opt/cowrie
sudo -u cowrie python3 -m venv /opt/cowrie/cowrie-env
sudo -u cowrie /opt/cowrie/cowrie-env/bin/python -m pip install --upgrade pip
sudo -u cowrie /opt/cowrie/cowrie-env/bin/python -m pip install cowrie
sudo -u cowrie -H bash -c 'cd /opt/cowrie && source /opt/cowrie/cowrie-env/bin/activate && cowrie init'
sudo cp /opt/cowrie/etc/cowrie.cfg /opt/cowrie/etc/cowrie.cfg.initial
```

Für den ersten lokalen Test `listen_endpoints = tcp:2222:interface=0.0.0.0` verwenden (Port 2222 bleibt per UFW geschlossen), Konfiguration sonst wie [`configs/cowrie/cowrie.cfg`](../configs/cowrie/cowrie.cfg); Rechte `cowrie:cowrie 0640`.

systemd-Unit aus [`configs/systemd/cowrie.service`](../configs/systemd/cowrie.service) installieren:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cowrie
sudo ss -ltnp | grep 2222
ssh -p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@127.0.0.1   # Fake-Passwort
```

## Schritt 10 – Vector liest Cowrie (VPS)

```bash
sudo setfacl -m u:vector:x  /opt/cowrie
sudo setfacl -m u:vector:x  /opt/cowrie/var
sudo setfacl -m u:vector:x  /opt/cowrie/var/log
sudo setfacl -m u:vector:rx /opt/cowrie/var/log/cowrie
sudo setfacl -m u:vector:r  /opt/cowrie/var/log/cowrie/cowrie.json
sudo setfacl -d -m u:vector:rX /opt/cowrie/var/log/cowrie
sudo -u vector tail -n 3 /opt/cowrie/var/log/cowrie/cowrie.json      # muss funktionieren

sudo cp configs/vector/vector-sender.yaml /etc/vector/vector.yaml    # Platzhalter ersetzen
sudo vector validate /etc/vector/vector.yaml
sudo systemctl enable --now vector
```

Auf dem Home-Server erscheinen `cowrie.*`-Events in `/var/log/honeypot/cowrie.json`.

## Schritt 11 – Cowrie-Regeln (Home-Server)

```bash
sudo cp wazuh/rules/cowrie_rules.xml /var/ossec/etc/rules/cowrie_rules.xml
sudo grep -RInE 'rule id="1102(1[0-9])"' /var/ossec/etc/rules      # jede ID genau einmal
sudo /var/ossec/bin/wazuh-logtest                                   # Tests aus wazuh/logtest/
sudo systemctl restart wazuh-manager
sudo grep '"id":"11021' /var/ossec/logs/alerts/alerts.json | tail -n 10
```

## Schritt 12 – Echten SSH auf 22222 über Tailscale verschieben (VPS)

```bash
sudo ufw allow in on tailscale0 from <ADMIN_TAILSCALE_IP> to <HONEYPOT_TAILSCALE_IP> \
  port 22222 proto tcp comment 'Admin SSH from desktop via Tailscale'
sudo mkdir -p /etc/systemd/system/ssh.socket.d
sudo cp configs/systemd/ssh.socket.d/honeypot-admin.conf /etc/systemd/system/ssh.socket.d/
sudo systemctl daemon-reload
sudo systemctl restart ssh.socket
sudo ss -ltnp | grep -E ':22|:2222|:22222'   # erwartet 0.0.0.0:22222 UND [::]:22222, kein sshd auf :22
```

In **neuer** Sitzung testen:

```powershell
ssh -i "$env:USERPROFILE\.ssh\id_ed25519_honeypot" -o IdentitiesOnly=yes -p 22222 ubuntu@<HONEYPOT_TAILSCALE_IP>
ssh -i "$env:USERPROFILE\.ssh\id_ed25519_honeypot" -o IdentitiesOnly=yes -o ConnectTimeout=5 -p 22222 ubuntu@<HONEYPOT_PUBLIC_IP>   # muss scheitern
```

## Schritt 13 – Cowrie auf Port 22 (VPS)

In `/opt/cowrie/etc/cowrie.cfg`: `listen_endpoints = tcp:22:interface=0.0.0.0`.

```bash
sudo mkdir -p /etc/systemd/system/cowrie.service.d
sudo cp configs/systemd/cowrie.service.d/override.conf /etc/systemd/system/cowrie.service.d/
sudo systemctl daemon-reload
sudo systemctl restart cowrie
sudo ss -ltnp | grep -E ':22|:2222|:22222'   # 0.0.0.0:22 -> twistd

# Veraltete TEMP-Regeln ersetzen (IPv6-Regel zuerst löschen, Nummern verschieben sich)
sudo ufw status numbered
sudo ufw delete <NR_22_V6>
sudo ufw delete <NR_22_V4>
sudo ufw allow 22/tcp comment 'Public Cowrie SSH honeypot'
```

## Schritt 14 – Egress Containment (VPS)

```bash
id cowrie                       # UID notieren (hier 1001)
TS=$(date +%Y%m%d-%H%M%S)
sudo cp -a /etc/ufw/before.rules  "/etc/ufw/before.rules.backup-$TS"
sudo cp -a /etc/ufw/before6.rules "/etc/ufw/before6.rules.backup-$TS"
sudo python3 configs/firewall/vps/apply-cowrie-egress.py
sudo grep -n -- '--uid-owner 1001' /etc/ufw/before.rules /etc/ufw/before6.rules   # je genau eine Zeile
sudo ufw reload
```

## Schritt 15 – Vector-Readiness-Drop-In (VPS)

```bash
sudo mkdir -p /etc/systemd/system/vector.service.d
sudo cp configs/systemd/vector.service.d/tailscale-readiness.conf /etc/systemd/system/vector.service.d/   # Platzhalter ersetzen
sudo systemctl daemon-reload
sudo systemctl restart vector
```

## Schritt 16 – Acceptance-Test

Reboot über die Tailscale-Admin-Sitzung, danach [`scripts/vps-healthcheck.sh`](../scripts/vps-healthcheck.sh) ausführen und einen externen Cowrie-Test (Fake-Credentials) mit harmlosen Kommandos durchführen. Ergebnisse: [`validation.md`](validation.md).
