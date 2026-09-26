#!/usr/bin/env bash
# Regressionstest der Cowrie-Regeln mit dem echten Wazuh-Regelwerk.
# Auf dem Home-SIEM als root ausführen:  sudo bash run-tests.sh [test-events.tsv]
#
# Nutzt den Unit-Test-Modus von wazuh-logtest (-U rule_id:level:decoder):
# Exit-Code 0 = das Event löst genau diese Regel mit diesem Level über den json-Decoder aus.
# Korrelationsregel 110219 (frequency) ist nicht enthalten – siehe README.md in diesem Ordner.
set -u
FILE="${1:-$(dirname "$0")/test-events.tsv}"
LOGTEST=/var/ossec/bin/wazuh-logtest
pass=0; fail=0
while IFS=$'\t' read -r rid lvl event; do
  [[ -z "$rid" || "$rid" == \#* ]] && continue
  if printf '%s\n' "$event" | "$LOGTEST" -q -U "${rid}:${lvl}:json" >/dev/null 2>&1; then
    echo "PASS  ${rid} (level ${lvl})"; pass=$((pass+1))
  else
    got=$(printf '%s\n' "$event" | "$LOGTEST" 2>/dev/null | grep -oE "id: '[0-9]+'" | tail -1)
    echo "FAIL  ${rid} (level ${lvl}) – tatsächlich: ${got:-kein Treffer}"; fail=$((fail+1))
  fi
done < "$FILE"
echo "----"
echo "Bestanden: $pass  Fehlgeschlagen: $fail"
[[ $fail -eq 0 ]]
