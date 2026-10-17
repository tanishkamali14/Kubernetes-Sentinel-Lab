#!/usr/bin/env bash
# Runs the Kyverno CLI unit tests in kyverno/tests against both policy files; no cluster needed.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${KYVERNO_CLI_IMAGE:-ghcr.io/kyverno/kyverno-cli:v1.19.1}"
if command -v kyverno >/dev/null; then
  kyverno test kyverno/tests
else
  docker run --rm -v "$PWD:/work:ro" -w /work "$IMAGE" test kyverno/tests
fi
