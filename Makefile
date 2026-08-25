# Telemetry-to-incident-report fine-tune. See docs/SCOPE.md.
#
# Local work uses Python 3.12 -- the ML stack has no 3.14 wheels yet.
# Training does not run here; it runs on Kaggle (SCOPE.md section 6).

PY      := python3.12
VENV    := .venv
BIN     := $(VENV)/bin
SCRATCH := .scratch

.DEFAULT_GOAL := help
.PHONY: help setup setup-eval data data-vcdb data-attack survey labels lint test clean clean-data

help:  ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# --- environment ----------------------------------------------------------

$(VENV):
	uv venv --python $(PY) $(VENV)

setup: $(VENV)  ## Create .venv and install local dependencies
	uv pip install --python $(BIN)/python -r requirements.txt
	@echo "done -- activate with: source $(BIN)/activate"

setup-eval: setup  ## Additionally install evaluation deps (pulls torch)
	uv pip install --python $(BIN)/python -r requirements-eval.txt

# --- data -----------------------------------------------------------------

data: data-vcdb data-attack  ## Download both raw corpora (~100 MB, gitignored)

data-vcdb:  ## Download VCDB records, VERIS schema, and the VERIS->ATT&CK mapping
	@mkdir -p data/raw/vcdb $(SCRATCH)
	@test -d $(SCRATCH)/VCDB || git clone --depth 1 https://github.com/vz-risk/VCDB.git $(SCRATCH)/VCDB
	@test -d $(SCRATCH)/veris || git clone --depth 1 https://github.com/vz-risk/veris.git $(SCRATCH)/veris
	@cp -r $(SCRATCH)/VCDB/data/json/validated data/raw/vcdb/
	@mkdir -p data/raw/vcdb/schema data/raw/vcdb/mappings
	@cp $(SCRATCH)/veris/verisc*.json data/raw/vcdb/schema/
	@cp $(SCRATCH)/veris/mappings/*.csv data/raw/vcdb/mappings/
	@echo "VCDB records: $$(ls data/raw/vcdb/validated | wc -l)"

data-attack:  ## Download the MITRE ATT&CK Enterprise STIX bundle
	@mkdir -p data/raw/attack
	curl -sSL -o data/raw/attack/enterprise-attack.json \
	  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
	@echo "ATT&CK bundle: $$(du -h data/raw/attack/enterprise-attack.json | cut -f1)"

# --- pipeline -------------------------------------------------------------

survey:  ## Survey the raw corpora; rewrites docs/DATA_SURVEY.md
	$(BIN)/python src/survey_vcdb.py

labels:  ## Validate the technique lookup and report coverage; rewrites docs/LABEL_COVERAGE.md
	$(BIN)/python -m src.label_coverage

# --- quality --------------------------------------------------------------

lint:  ## Lint and format-check src/ and tests/
	$(BIN)/ruff check src/ tests/
	$(BIN)/ruff format --check src/ tests/

test:  ## Run the test suite
	$(BIN)/pytest -q

# --- housekeeping ---------------------------------------------------------

clean:  ## Remove caches, venv, and clone scratch (keeps downloaded data)
	rm -rf $(VENV) $(SCRATCH) .ruff_cache .pytest_cache
	find . -name __pycache__ -type d -prune -exec rm -rf {} +

clean-data:  ## Delete downloaded corpora. Re-fetch with `make data`.
	rm -rf data/raw/vcdb data/raw/attack
