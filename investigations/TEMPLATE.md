# HP-XXX – <Kurztitel, z. B. „Automatisierter SSH-Login mit Shell-Check">

| Feld | Wert |
|---|---|
| Analyst | |
| Datum der Analyse | |
| Sensor | honeypot-vps |
| Quelle | `ATTACKER-IP-XX` (anonymisiert) |
| Session-ID(s) | |
| Zeitraum (UTC) | |
| Session-Dauer | |
| Einstufung | automatisiert / interaktiv / unklar |

## 1. Zusammenfassung

<2–4 Sätze: Was ist passiert, wie relevant ist es?>

## 2. Timeline

| Zeit (UTC) | Event | Details | Wazuh-Regel |
|---|---|---|---|
| | `cowrie.session.connect` | | 110211 |
| | `cowrie.client.version` | | – |
| | `cowrie.login.success` / `.failed` | Username: …, Passwort: `<REDACTED_PASSWORD>` | 110213 / 110212 |
| | `cowrie.command.input` | `…` | 110214 |
| | `cowrie.session.closed` | | – |

## 3. Ausgeführte Kommandos

```text
<Kommandos in Reihenfolge; URLs defanged>
```

## 4. Downloads / Uploads

| Typ | Dateiname | SHA-256 | Größe | Bemerkung |
|---|---|---|---|---|
| | | | | Egress-Sperre aktiv – Nachladen durch Cowrie nicht möglich |

## 5. Indicators of Compromise

| Typ | Wert (anonymisiert/defanged) | Kontext |
|---|---|---|
| IP | `ATTACKER-IP-XX` | |
| SSH-Client-Version | | |
| HASSH | | |
| Kommando-Muster | | |

## 6. MITRE ATT&CK Mapping

| Taktik | Technik | Beobachtung | Begründung |
|---|---|---|---|
| | | | |

## 7. Detection Coverage

| Schritt | Erkannt durch | Lücke / Verbesserung |
|---|---|---|
| | | |

## 8. Analyst Conclusion

<Bewertung, Hypothesen klar als solche gekennzeichnet, empfohlene Regel- oder Dashboard-Anpassungen>

---
*Hinweis: `cowrie.login.success` bedeutet, dass Cowrie die simulierten Credentials akzeptiert hat. Der Angreifer befand sich in einer emulierten Shell, nicht auf dem Betriebssystem des VPS.*
