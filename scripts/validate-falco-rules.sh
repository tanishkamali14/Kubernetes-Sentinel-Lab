#!/usr/bin/env bash
# Loads every falco/*.yaml on top of the default ruleset with `falco -V`; no cluster or kernel driver needed.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGE="${FALCO_IMAGE:-falcosecurity/falco:0.45.0}"
validate=(-V /etc/falco/falco_rules.yaml)
for f in falco/*.yaml; do validate+=(-V "/rules/$(basename "$f")"); done
docker run --rm --entrypoint /usr/bin/falco -v "$PWD/falco:/rules:ro" "$IMAGE" "${validate[@]}"
