#!/usr/bin/env bash
# Usage: collect-and-correlate.sh [--fail-on-gap]
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p runtime-data
docker exec runtime-security-control-plane cat /var/log/kubernetes/kube-apiserver-audit.log > runtime-data/audit.jsonl
kubectl logs -n falco -l app.kubernetes.io/name=falco --all-containers=true --since=24h \
  | grep -E '^\s*\{' > runtime-data/falco.jsonl || true
inputs=(--audit runtime-data/audit.jsonl --falco runtime-data/falco.jsonl)
run=()
[ -s runtime-data/scenario-run.jsonl ] && run=(--run runtime-data/scenario-run.jsonl)
gap=()
[ "${1:-}" = --fail-on-gap ] && gap=(--fail-on-gap)
# ${arr[@]+"${arr[@]}"} keeps empty arrays safe under set -u on bash < 4.4.
echo '--- exec/shell correlation'; python3 correlator/correlate.py "${inputs[@]}" --window-seconds 30
echo '--- metrics'; python3 correlator/metrics.py "${inputs[@]}" --window-seconds 30
echo '--- incidents'; python3 correlator/incidents.py "${inputs[@]}" --format table
python3 correlator/report.py "${inputs[@]}" ${run[@]+"${run[@]}"} --out runtime-data/report.html
echo '--- scenario coverage'
python3 correlator/detection_coverage.py "${inputs[@]}" ${run[@]+"${run[@]}"} ${gap[@]+"${gap[@]}"} --format table
echo 'Snapshots and report.html saved under runtime-data/.'
