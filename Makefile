# Linux/macOS convenience targets. Windows users run the matching scripts/*.ps1 files.
PY ?= python3

.PHONY: test test-policies validate-falco sync-falco sync-falco-check check up deploy attack collect report down

test:            ## offline unit and consistency tests (no cluster)
	$(PY) -m unittest discover -s tests -v

test-policies:   ## Kyverno CLI policy tests (needs docker or the kyverno binary)
	bash scripts/test-policies.sh

validate-falco:  ## load falco/*.yaml with `falco -V` (needs docker)
	bash scripts/validate-falco-rules.sh

sync-falco:      ## regenerate helm/falco-values.yaml from falco/*.yaml
	$(PY) scripts/sync_falco_values.py

check: test sync-falco-check test-policies validate-falco

sync-falco-check:
	$(PY) scripts/sync_falco_values.py --check

up:
	bash scripts/up.sh

deploy:
	bash scripts/deploy-workload.sh

attack:
	bash scripts/attack-scenarios.sh

collect:         ## snapshot logs, then correlate, score incidents, check coverage, write the report
	bash scripts/collect-and-correlate.sh

report: collect

down:
	kind delete cluster --name runtime-security
