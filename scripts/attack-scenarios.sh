#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p runtime-data
: > runtime-data/scenario-run.jsonl
read -r NS POD < <(python3 -c 'import json; w = json.load(open("scenarios/scenarios.json"))["workload"]; print(w["namespace"], w["pod"])')
now() { date -u +%Y-%m-%dT%H:%M:%S.%3NZ; }
failures=0
while IFS=$'\t' read -r id kind target; do
  started=$(now)
  echo "[$id] $kind: $target"
  if [ "$kind" = admission ]; then
    if out=$(kubectl apply -f "$target" 2>&1); then result=admitted; failures=$((failures + 1)); else result=rejected; fi
    echo "$out"
  else
    if kubectl exec -n "$NS" "$POD" -- sh -c "$target"; then result=ok; else result=nonzero; fi
  fi
  printf '{"id":"%s","started":"%s","finished":"%s","result":"%s"}\n' "$id" "$started" "$(now)" "$result" >> runtime-data/scenario-run.jsonl
done < <(python3 correlator/scenarios.py --tsv)
if [ "$failures" -gt 0 ]; then echo "Policy failure: $failures admission scenario(s) were admitted." >&2; exit 1; fi
echo 'Wait several seconds for Falco output to flush, then run collect-and-correlate.sh.'
