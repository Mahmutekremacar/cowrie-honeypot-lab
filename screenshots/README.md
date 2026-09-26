# Screenshots

> Nur **anonymisierte** Screenshots gehören in diesen Ordner. Rohaufnahmen bleiben lokal in `screenshots/raw/` (per `.gitignore` ausgeschlossen). Regeln: [`../SECURITY.md`](../SECURITY.md#3-screenshots).

## Geplante Aufnahmen (Phase 2)

| Datei | Inhalt | Zu schwärzen |
|---|---|---|
| `01-dashboard-overview.png` | Dashboard „Cowrie Honeypot SOC" (KPIs, Zeitreihe, Top-Listen) | Source-IPs, Passwort-Panel komplett |
| `02-wazuh-alert-110214.png` | Alert-Details mit `rule.id`, `rule.mitre`, `data.input`, `location` | `data.src_ip`, `agent/manager.name` falls identifizierend |
| `03-custom-rules.png` | `cowrie_rules.xml` bzw. Regelübersicht im Dashboard | – |
| `04-mitre-mapping.png` | MITRE-ATT&CK-Ansicht gefiltert auf `rule.groups:cowrie` | IPs |
| `05-listeners.png` | `ss -ltnp`: `:22` → twistd, `:22222` → sshd | Hostname, PIDs optional |
| `06-tailscale-only-ssh.png` | erfolgreicher Login über Tailscale:22222, fehlgeschlagener über Public-IP:22222 | alle IPs, Host-Key-Fingerprint, Windows-Benutzername im Pfad |
| `07-segmentation-nc.png` | `nc`-Tests: 5× timeout, 6514 succeeded | Tailscale-IPs |
| `08-egress-containment.png` | iptables-Ketten + `GOOD`-Tests | – |
| `09-vector-pipeline.png` | `ss` mit `ESTAB` Tailscale-IP → 6514, `ip route get` | Tailscale-IPs |
| `10-healthcheck-after-reboot.png` | Ausgabe von `scripts/vps-healthcheck.sh` | IPs |
| `11-cowrie-fake-shell.png` | `root@web01` in der emulierten Shell (eigener Test) | IP, eingegebenes Passwort |
| `12-tailscale-policy.png` | Policy mit Grants und Tests in der Admin-Konsole | Tailnet-Name, E-Mail-Adresse |
