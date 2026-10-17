#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
kubectl apply -f examples/workload.yaml
kubectl wait --for=condition=Ready pod/runtime-lab --timeout=180s
echo 'runtime-lab is ready.'
