#!/usr/bin/env python3
"""
Fügt die UID-basierte Egress-Sperre für den Cowrie-User in die UFW-Regeldateien ein.

Genau dieses Skript wurde im Projekt auf dem VPS ausgeführt (als root, per Heredoc).
Es ist idempotent: bereits vorhandene Cowrie-/Loopback-Zeilen werden vor dem
Einfügen entfernt, sodass mehrfaches Ausführen keine Duplikate erzeugt.

Ergebnis je Kette (ufw-before-output bzw. ufw6-before-output):
    RELATED,ESTABLISHED  -> ACCEPT   (unverändert)
    --uid-owner 1001     -> REJECT   (neu)
    -o lo                -> ACCEPT   (hinter die Cowrie-Sperre verschoben)

Vorher Backup anlegen:
    TS=$(date +%Y%m%d-%H%M%S)
    sudo cp -a /etc/ufw/before.rules  "/etc/ufw/before.rules.backup-$TS"
    sudo cp -a /etc/ufw/before6.rules "/etc/ufw/before6.rules.backup-$TS"

Danach prüfen und erst dann laden:
    sudo grep -n -- '--uid-owner 1001' /etc/ufw/before.rules /etc/ufw/before6.rules
    sudo ufw reload
"""
from pathlib import Path

configs = [
    ("/etc/ufw/before.rules", "ufw-before-output"),
    ("/etc/ufw/before6.rules", "ufw6-before-output"),
]

uid = "1001"  # id cowrie -> uid=1001(cowrie)

for filename, chain in configs:
    path = Path(filename)
    lines = path.read_text().splitlines()

    established = (
        f"-A {chain} -m conntrack "
        "--ctstate RELATED,ESTABLISHED -j ACCEPT"
    )
    block_cowrie = f"-A {chain} -m owner --uid-owner {uid} -j REJECT"
    loopback = f"-A {chain} -o lo -j ACCEPT"

    # Idempotenz: vorhandene Zeilen entfernen.
    lines = [line for line in lines if line not in (block_cowrie, loopback)]

    if established not in lines:
        raise SystemExit(f"ERROR: expected ESTABLISHED rule not found in {filename}")

    pos = lines.index(established)

    # Reihenfolge ist entscheidend:
    # 1. Bestehende Verbindungen dürfen antworten.
    # 2. Cowrie darf nichts Neues initiieren.
    # 3. Alle übrigen Prozesse behalten Loopback-Zugriff.
    lines[pos + 1:pos + 1] = [block_cowrie, loopback]

    path.write_text("\n".join(lines) + "\n")
    print(f"Updated {filename}")
