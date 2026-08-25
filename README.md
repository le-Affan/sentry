# Telemetry-to-Incident-Report

Fine-tunes a small open-weight LLM to turn a raw SIEM-style telemetry blob into a
structured, six-section Markdown incident report. Input is one flat text export per
incident — metadata, assets, accounts, a time-ordered event log, and detection
enrichment. Output is fixed-heading Markdown covering summary, affected assets, MITRE
ATT&CK technique, severity, root cause, and recommended actions. Defensive analysis
only; the model summarizes and classifies incidents that already happened.

Full input/output specs, parsing rules, evaluation plan, and the fixed project
constraints live in [`docs/SCOPE.md`](docs/SCOPE.md).

## Phases

1. **Scope** — lock the input spec, output spec, parsing rules, and constraints.
2. **Data pull** — pull the VERIS Community Database and the MITRE ATT&CK corpus.
3. **Dataset build** — render VCDB records into telemetry blobs and reference reports; split ~900 train / 100 test.
4. **Baseline** — evaluate the untrained base model on the test split.
5. **Train** — single 4-bit QLoRA run on Kaggle GPU.
6. **RAG** — add ATT&CK retrieval at inference to ground technique attribution.
7. **Eval** — score baseline vs. fine-tuned vs. fine-tuned+RAG on the same test split.
8. **Demo** — end-to-end walkthrough: paste a blob, get a report.

## Setup

Local work needs Python 3.12 — much of the ML stack has no 3.14 wheels yet.
Training does not run locally; it runs on Kaggle (see the fixed constraints in
`docs/SCOPE.md` §6).

```sh
make setup          # create .venv and install local dependencies
make data           # download VCDB + MITRE ATT&CK (~100 MB, gitignored)
make survey         # regenerate docs/DATA_SURVEY.md
make test lint      # checks
make help           # all targets
```

Secrets go in `.env` (gitignored) — copy `.env.example` and fill it in. Only
needed for pushing to Kaggle from the CLI.

Dependencies are split by where they run:

| File | Scope |
|---|---|
| `requirements.txt` | Local: dataset build, tokenizer, RAG index. No torch. |
| `requirements-eval.txt` | Scoring metrics. Pulls torch. |
| `requirements-train.txt` | Kaggle only — do not install locally. |

## Layout

| Path | Contents |
|---|---|
| `docs/` | Specs and project documentation — start with `SCOPE.md` |
| `data/raw/` | Downloaded corpora (gitignored; `make data` refetches) |
| `data/interim/`, `data/processed/` | Build intermediates and final splits (gitignored) |
| `src/` | Reusable code; `config.py` holds the fixed constraints |
| `notebooks/` | Kaggle training and evaluation notebooks |
| `outputs/` | Model artifacts, generations, evaluation results (gitignored) |
| `tests/` | Guards against drift between docs and code |
