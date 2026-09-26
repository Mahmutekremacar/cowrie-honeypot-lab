# Lessons Learned

## Technisch

1. **„Gestartet" ist nicht „bereit".** `After=tailscaled.service` garantiert nur die Startreihenfolge. Für Dienste, die von einem Overlay-Netz abhängen, muss die tatsächliche Bereitschaft (hier: Route über `tailscale0`) geprüft werden. Ein Reboot-Test nach **jeder** größeren Änderung hat den Fehler gefunden, bevor er im Betrieb unbemerkt Telemetrie gekostet hätte.

2. **Distributionsdetails schlagen Tutorials.** Ubuntu 24.04 verwaltet den SSH-Port über `ssh.socket`. Wer nur `Port` in `sshd_config` ändert, verschiebt nichts. Und `BindIPv6Only=ipv6-only` in der Basis-Unit macht aus einem vermeintlichen Dual-Stack-Listener einen reinen IPv6-Socket.

3. **Die installierte Version ist die Wahrheit.** `cowrie start -n` stand in Dokumentation, existiert aber in der installierten CLI nicht. Die Fehlersuche wurde erst durch den identischen manuellen Aufruf eindeutig – statt am systemd-Unit zu raten.

4. **Reihenfolge in Firewall-Ketten ist Sicherheitslogik.** Die Egress-Sperre funktioniert nur, weil sie *nach* RELATED,ESTABLISHED und *vor* dem Loopback-Allow steht. An anderer Stelle hätte sie entweder den Honeypot lahmgelegt oder einen lokalen Pivot auf den echten SSH erlaubt.

5. **Egress prozessbezogen statt pauschal.** Ein globales `deny outgoing` hätte Tailscale, DNS, apt und Vector gefährdet. Die UID-basierte Regel trifft genau den Prozess, von dem das Risiko ausgeht.

6. **Least Privilege ist oft nur eine Zeile mehr.** `CAP_NET_BIND_SERVICE` per systemd statt `setcap` auf den Interpreter; ACLs statt `chmod 777`. Beides kostet kaum Aufwand, verhindert aber systemweite Nebenwirkungen.

7. **Container sind nicht automatisch Isolation.** Docker-Portfreigaben können UFW umgehen. Wo die gesamte Sicherheitslogik auf Host-Firewall-Regeln beruht, war der native Betrieb als unprivilegierter User die konsistentere Wahl.

8. **Erst die Pipeline beweisen, dann den Sensor.** Die Kette VPS → Tailscale → Receiver → Datei → Decoder → Regel → Alert wurde mit synthetischen `lab.*`-Events nachgewiesen, bevor Cowrie existierte. Fehler ließen sich so eindeutig einer Schicht zuordnen.

9. **Negative Tests sind die eigentlichen Sicherheitstests.** Dass 6514 funktioniert, beweist wenig. Aussagekräftig ist, dass 22/443/1514/1515/55000 **nicht** funktionieren – und dass `Connection refused` (Pfad erlaubt) von `timed out` (Pfad blockiert) unterschieden wird.

10. **ID-Bereiche für Custom Rules pro Projekt planen.** Die Kollision mit einer älteren Regel fiel nur durch die Warnung in `wazuh-logtest` auf.

11. **Präzise Sprache ist Teil der Sicherheit.** „One-Way" ist hier keine Data Diode; `login.success` in Cowrie ist kein Systemzugriff; „Disk-Buffer" ist keine Zustellgarantie; Port 6514 heißt nicht TLS. Überzogene Formulierungen erzeugen falsche Sicherheitsannahmen.

## Arbeitsweise

12. **Bestehende Sitzung offen halten, in zweiter Sitzung testen.** Jede SSH- und Firewall-Änderung wurde so umgesetzt – es gab keinen Lockout.

13. **Hostnamen eindeutig vergeben.** Zwei Fehler (Tests und eine UFW-Regel auf dem falschen Host) gingen auf verwechselte Terminals zurück. Eindeutige Namen und ein Blick auf den Prompt sind billiger als jede Rückabwicklung.

14. **Bestehende Produktivsysteme nicht nebenbei „härten".** Das pauschale `default deny` auf dem Home-Server wurde bewusst zurückgestellt, bis legitime Quellen inventarisiert sind.

15. **Secrets gehören nicht in Terminals, Chats oder History.** Tailscale-Auth-Key per `read -rsp`, keine Keys oder Passwörter in Logs oder Nachrichten; versehentlich geteilte Werte werden als kompromittiert behandelt und rotiert.
