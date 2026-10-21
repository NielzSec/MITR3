.PHONY: help doctor fixtures test demo bootstrap clean e2e

LAB := $(CURDIR)
WORK ?= /tmp/opencode/fwlab-demo
FW ?= $(LAB)/fixtures/dist/fw-v1.tar.gz
FW2 ?= $(LAB)/fixtures/dist/fw-v2.tar.gz

help:
	@echo "make doctor      check host tooling"
	@echo "make fixtures    build the synthetic vulnerable/fixed firmware pair"
	@echo "make test        run the unit suite"
	@echo "make demo        full pipeline: inspect -> extract -> inventory -> queue -> diff -> report"
	@echo "make bootstrap   clone the external RE toolkit into vendor/"
	@echo "make clean       remove build artifacts and demo output"

doctor:
	@$(LAB)/bin/fwlab doctor

fixtures:
	@bash $(LAB)/fixtures/build_fixtures.sh

test:
	@python3 -m unittest discover -s $(LAB)/tests -v

demo: fixtures
	@$(LAB)/bin/fwlab demo --fixture $(FW) --against $(FW2) --workdir $(WORK)

e2e: demo
	@echo "--- report ---"
	@sed -n '1,60p' $(WORK)/report.md

bootstrap:
	@bash $(LAB)/scripts/bootstrap_repos.sh

clean:
	@rm -rf $(LAB)/fixtures/build $(LAB)/fixtures/dist $(WORK)
	@find $(LAB) -name '__pycache__' -type d -prune -exec rm -rf {} +
	@echo "clean"
