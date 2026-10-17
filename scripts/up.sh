#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
for tool in docker kind kubectl helm python3; do
  command -v "$tool" >/dev/null || { echo "Required command not found: $tool" >&2; exit 1; }
done
docker info >/dev/null
if ! kind get clusters | grep -qx runtime-security; then
  kind create cluster --config kind/kind-config.yaml --wait 180s
else
  kubectl config use-context kind-runtime-security
fi
helm repo add kyverno https://kyverno.github.io/kyverno/ --force-update
helm repo add falcosecurity https://falcosecurity.github.io/charts --force-update
helm repo update
# Chart versions the lab was checked against (Kyverno 1.19.1, Falco 0.45.0); override via environment.
KYVERNO_CHART_VERSION="${KYVERNO_CHART_VERSION:-3.9.1}"
FALCO_CHART_VERSION="${FALCO_CHART_VERSION:-9.2.0}"
helm upgrade --install kyverno kyverno/kyverno --version "$KYVERNO_CHART_VERSION" -n kyverno --create-namespace --wait --timeout 8m
kubectl apply -f kyverno/baseline-policies.yaml -f kyverno/advanced-policies.yaml
helm upgrade --install falco falcosecurity/falco --version "$FALCO_CHART_VERSION" -n falco --create-namespace \
  --set driver.kind=modern_ebpf --set tty=true -f helm/falco-values.yaml --wait --timeout 10m
echo 'Cluster, API audit logging, Kyverno, and Falco are installed.'
