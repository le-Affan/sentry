# Sentry

Fine-tuning a small open-weight LLM to turn raw security telemetry into a structured
incident report. `Qwen2.5-3B-Instruct` + a 4-bit QLoRA adapter takes a SIEM-style
telemetry blob and emits six-section Markdown: summary, affected assets, MITRE ATT&CK
technique, severity, root cause, and recommended actions. Defensive analysis only — the
model summarises and classifies incidents that already happened.

## → Start with [docs/PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md)

That is the single entry point: what the project does, the full pipeline, a directory
map, how to inspect each stage, and the order in which to read every other document.

## Headline result

40 held-out test incidents, base vs the same model with the adapter. Greedy decoding,
fixed seed, identical prompt.

| | Base | Tuned |
|---|---|---|
| ROUGE-L | 0.2416 | **0.5104** |
| BERTScore | 0.8150 | **0.9102** |
| Format adherence | 30.0% | **100.0%** |
| Technique accuracy | 2.5% | **90.0%** *(baseline 17.5%)* |
| Severity accuracy | 47.5% | **82.5%** *(baseline 66.0%)* |
| Reports free of invented entities | 95.0% | 95.0% |

Several limitations are load-bearing — read
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) before citing any of this.

## Documentation

| Doc | What it covers |
|---|---|
| [PROJECT_OVERVIEW.md](docs/PROJECT_OVERVIEW.md) | **Start here.** Pipeline, directory map, reading order |
| [SCOPE.md](docs/SCOPE.md) | Input/output specs, parsing rules, evaluation plan, fixed constraints |
| [DATA_SOURCES.md](docs/DATA_SOURCES.md) | Every raw input: licence, URL, pinned commit, retrieval date |
| [DATA_SURVEY.md](docs/DATA_SURVEY.md) | What VCDB contains, and why telemetry had to be synthesised |
| [LABEL_COVERAGE.md](docs/LABEL_COVERAGE.md) | Labelling method, coverage, class balance |
| [TEMPLATING_DESIGN.md](docs/TEMPLATING_DESIGN.md) | Synthetic chain design, and the leakage it failed to prevent |
| [DATASET_STATS.md](docs/DATASET_STATS.md) | The finished 400-pair corpus in numbers |
| [RESULTS_SUMMARY.md](docs/RESULTS_SUMMARY.md) | Paper-ready results table and interpretation |
| [EVAL_RESULTS.md](docs/EVAL_RESULTS.md) | Full results with worked base-vs-tuned examples |
| [LIMITATIONS.md](docs/LIMITATIONS.md) | Every limitation, with evidence and what remains valid |
| [REPRODUCE.md](docs/REPRODUCE.md) | Step-by-step regeneration from a cold clone |

## Quick start

Python 3.12 (not 3.14 — the ML stack has no wheels for it).

```sh
make setup        # create .venv and install local dependencies
make help         # list every pipeline target
make test lint    # 7 tests, lint clean
```

Evaluation needs no GPU and no Kaggle account — the model predictions are committed:

```sh
make setup-eval && make eval
```

Full instructions, including credentials and the GPU stages, are in
[docs/REPRODUCE.md](docs/REPRODUCE.md).

## Demo

A local web UI for browsing the 40 test scenarios and their generated reports.

```sh
make demo         # then open http://127.0.0.1:8000
```

Reports are real fine-tuned-model output, generated on a Kaggle Tesla T4 and
committed to this repository (`data/processed/preds_tuned.jsonl`). The demo serves
those — it does not run the model, so it needs no GPU and no downloads. A blob that
differs from a known scenario returns HTTP 501 rather than a fabricated answer;
regenerating predictions for new telemetry requires the Kaggle path in
[docs/REPRODUCE.md](docs/REPRODUCE.md) §6.

## Layout

```
demo/         Single-file static frontend for the local demo.
docs/         All documentation. Start at PROJECT_OVERVIEW.md.
labels/       Our labelling decisions, version-controlled as data.
src/          All logic. Run as modules: python -m src.<name>
notebooks/    Thin Kaggle runners (training, prediction). No logic.
data/raw/     Downloaded corpora (gitignored; `make data` refetches).
data/processed/  Build outputs (gitignored, except the tracked prediction files).
outputs/      Model artifacts (gitignored).
tests/        Guards against docs and code drifting apart.
```

## Pipeline

`VCDB + ATT&CK` → labelling → templating → synthetic blobs → Gemini reference reports →
Qwen2.5-3B QLoRA fine-tune (Kaggle T4) → base-vs-tuned evaluation.

RAG was scoped but **never implemented**; it remains future scope.
