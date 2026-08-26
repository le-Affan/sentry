# Sentry — Project Overview

*Last updated 2026-08-27. Start here.*

This is the entry point for the whole project. Everything below is traceable to
something actually run in this repository; nothing is aspirational.

---

## 1. What Sentry is

Sentry is a fine-tuned small language model that turns a raw security telemetry blob
into a structured incident report. The input is one flat text export describing a single
incident — metadata, an asset inventory, an account list, a time-ordered event log, and
detection enrichment — of the kind a SIEM produces. The output is Markdown with exactly
six fixed headings: **Summary**, **Affected Assets**, **Attack Technique**, **Severity**,
**Root Cause**, and **Recommended Actions**. The model is `Qwen2.5-3B-Instruct` adapted
with a 4-bit QLoRA adapter trained on 360 examples. The work is defensive and academic:
it summarises and classifies incidents that already happened, and produces no offensive
capability.

---

## 2. The pipeline, end to end

Each stage was run once and its output is recorded in a document.

| # | Stage | What happens | Produces | Doc |
|---|---|---|---|---|
| 1 | **Source survey** | Pull the VERIS Community Database (10,596 validated records) and MITRE ATT&CK Enterprise 19.2. Measure what VCDB actually contains. | `data/raw/` | [DATA_SURVEY.md](DATA_SURVEY.md), [DATA_SOURCES.md](DATA_SOURCES.md) |
| 2 | **Labelling** | Assign one ATT&CK technique per record using a hand-curated 21-row lookup. The official VERIS→ATT&CK crosswalk was evaluated and rejected. | `labels/*.yaml` | [LABEL_COVERAGE.md](LABEL_COVERAGE.md) |
| 3 | **Templating design** | Decide how synthetic event chains are built so the generator does not trivially leak the label. | `src/chains.yaml` | [TEMPLATING_DESIGN.md](TEMPLATING_DESIGN.md) |
| 4 | **Dataset build** | Select 400 records, render each into a telemetry blob within an 850-token budget. | `data/processed/blobs.jsonl` | [DATASET_STATS.md](DATASET_STATS.md) |
| 5 | **Reference reports** | Generate the target report for each blob with the Google Gemini API (`gemini-3.1-flash-lite`), validating format and grounding on every generation. | `data/processed/reports.jsonl` | [DATASET_STATS.md](DATASET_STATS.md) |
| 6 | **SFT splits** | Emit Qwen chat-format pairs, token-checked against `max_seq_len` 1536. | `train.jsonl` (360), `test.jsonl` (40) | [DATASET_STATS.md](DATASET_STATS.md) |
| 7 | **QLoRA fine-tune** | 3 epochs on a Kaggle Tesla T4. 63 steps, 258 minutes. | LoRA adapter | [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md) |
| 8 | **Prediction** | Run base and base+adapter over the same 40 test blobs, greedy, fixed seed. | `preds_base.jsonl`, `preds_tuned.jsonl` | [EVAL_RESULTS.md](EVAL_RESULTS.md) |
| 9 | **Evaluation** | Score both against the references. | `docs/EVAL_RESULTS.md` | [EVAL_RESULTS.md](EVAL_RESULTS.md) |

**RAG was scoped but never implemented.** ATT&CK is used only to validate technique IDs
and names during labelling. There is no retrieval step in any script, notebook, or
result. Treat every mention of RAG in this repository as future scope.

### Headline result

| | Base | Tuned |
|---|---|---|
| ROUGE-L | 0.2416 | **0.5104** |
| BERTScore | 0.8150 | **0.9102** |
| Format adherence | 30.0% | **100.0%** |
| Technique accuracy | 2.5% | **90.0%** *(baseline 17.5%)* |
| Severity accuracy | 47.5% | **82.5%** *(baseline 66.0%)* |

Read these alongside [LIMITATIONS.md](LIMITATIONS.md) — several are load-bearing.

---

## 3. Directory map

```
.
├── README.md               Points here.
├── Makefile                Every pipeline stage as a target. `make help` lists them.
├── docs/                   All documentation (see reading order below).
├── labels/                 Our labelling decisions, version-controlled as data.
│   ├── technique_lookup.yaml     21 VERIS varieties → one ATT&CK technique each,
│   │                             with rationale, confidence, and tie-break priority.
│   └── excluded_varieties.yaml   Varieties deliberately dropped, with reasons.
├── src/                    All logic. Scripts are run as modules: `python -m src.X`.
│   ├── config.py                 Fixed constraints in one place (model, seq len, splits).
│   ├── survey_vcdb.py            Stage 1 → docs/DATA_SURVEY.md
│   ├── label_coverage.py         Stage 2 → docs/LABEL_COVERAGE.md
│   ├── chains.yaml               34 event-chain skeletons. Data, not code.
│   ├── select_records.py         Stage 4 → data/processed/selected.jsonl
│   ├── templater.py              Stage 4 → data/processed/blobs.jsonl
│   ├── pilot_leakage.py          Leakage test from TEMPLATING_DESIGN.md §6
│   ├── generate_reports.py       Stage 5 (Gemini) → reports.jsonl
│   ├── dataset_stats.py          Stage 6 → docs/DATASET_STATS.md
│   ├── build_sft.py              Stage 6 → train.jsonl / test.jsonl
│   ├── train_qlora.py            Stage 7. Hyperparameters are constants at the top.
│   ├── generate_predictions.py   Stage 8
│   └── evaluate.py               Stage 9 → docs/EVAL_RESULTS.md
├── notebooks/              Thin Kaggle runners. No logic lives here.
│   ├── train_kaggle.ipynb        Runs src/train_qlora.py on a Kaggle GPU.
│   └── predict_kaggle.ipynb      Runs src/generate_predictions.py, both variants.
├── data/
│   ├── raw/                Downloaded corpora. Gitignored; `make data` refetches.
│   └── processed/          Build outputs. Gitignored EXCEPT the two prediction files,
│                           which are tracked because they cost GPU time to reproduce.
├── outputs/                Model artifacts. Gitignored.
└── tests/                  Guards against docs and code drifting apart.
```

---

## 4. How to inspect each stage without re-running training

Nothing here needs a GPU. Full regeneration instructions are in
[REPRODUCE.md](REPRODUCE.md).

| To inspect | Do this |
|---|---|
| What VCDB contains | Read [DATA_SURVEY.md](DATA_SURVEY.md), or `make survey` |
| Our technique labels | Read `labels/technique_lookup.yaml` — every row has a rationale |
| Label coverage and class balance | Read [LABEL_COVERAGE.md](LABEL_COVERAGE.md), or `make labels` |
| Why the chains look as they do | Read [TEMPLATING_DESIGN.md](TEMPLATING_DESIGN.md) |
| The leakage measurement | `make pilot` (needs `blobs.jsonl`; see REPRODUCE.md) |
| A real telemetry blob | `head -1 data/processed/blobs.jsonl \| python -m json.tool` |
| A reference report | `head -1 data/processed/reports.jsonl \| python -m json.tool` |
| Corpus statistics | Read [DATASET_STATS.md](DATASET_STATS.md), or `make stats` |
| Training loss curve | [RESULTS_SUMMARY.md](RESULTS_SUMMARY.md) §Training |
| Model predictions | `data/processed/preds_base.jsonl`, `preds_tuned.jsonl` (tracked in git) |
| Final scores | Read [EVAL_RESULTS.md](EVAL_RESULTS.md), or `make eval` |

### Kaggle artifacts

Both GPU stages ran as private Kaggle kernels under the account `l0affan`:

| Kernel | Stage | Result |
|---|---|---|
| `l0affan/sentry-qlora-train` | Training (stage 7) | Tesla T4, 63 steps, 258.3 min |
| `l0affan/sentry-qlora-predict` | Prediction (stage 8) | 0.91h GPU, 80 generations |
| Dataset `l0affan/sentry-sft-data-v1` | Input to both | train/test + `src/` |

They are private to that account. The prediction outputs are committed to this repo, so
**the evaluation is fully reproducible without Kaggle access.**

---

## 5. Reading order

1. **[PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md)** — this file.
2. **[SCOPE.md](SCOPE.md)** — the input and output specifications, parsing rules,
   evaluation plan, and the fixed constraints. The contract everything else obeys.
3. **[DATA_SOURCES.md](DATA_SOURCES.md)** — every raw input with license, URL, pinned
   commit, and retrieval date. Needed for citation.
4. **[DATA_SURVEY.md](DATA_SURVEY.md)** — what VCDB actually contains, and the gap
   analysis explaining why the telemetry had to be synthesised.
5. **[LABEL_COVERAGE.md](LABEL_COVERAGE.md)** — how records were labelled and how the
   classes are distributed.
6. **[TEMPLATING_DESIGN.md](TEMPLATING_DESIGN.md)** — how synthetic chains are built,
   and §7 the measured leakage that the design failed to prevent.
7. **[DATASET_STATS.md](DATASET_STATS.md)** — the finished corpus in numbers.
8. **[RESULTS_SUMMARY.md](RESULTS_SUMMARY.md)** — paper-ready results.
9. **[EVAL_RESULTS.md](EVAL_RESULTS.md)** — full results with worked examples.
10. **[LIMITATIONS.md](LIMITATIONS.md)** — read before writing any claim.
11. **[REPRODUCE.md](REPRODUCE.md)** — step-by-step regeneration.
