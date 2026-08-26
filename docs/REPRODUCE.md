# Reproducing Sentry

*Last updated 2026-08-27. Written for someone starting from a fresh clone with no prior
context.*

Read [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) first if you have not.

**You do not need a GPU to reproduce the evaluation.** The model predictions are
committed to this repository. Only stages 7 and 8 need Kaggle, and only if you want to
retrain from scratch.

---

## 0. What needs what

| Stage | Command | Needs |
|---|---|---|
| 1 Download corpora | `make data` | Internet, ~100 MB, ~2 min |
| 2 Survey sources | `make survey` | Local only |
| 3 Label coverage | `make labels` | Local only |
| 4 Select + render blobs | `make blobs` | Local; downloads the Qwen **tokenizer** (~12 MB, not the model) |
| 5 Leakage pilot | `make pilot` | Local only |
| 6 Reference reports | `make reports` | **Gemini API key**, ~45 min (rate-limited) |
| 7 Corpus stats + SFT splits | `make stats && make sft` | Local only |
| 8 **Train** | Kaggle kernel | **Kaggle GPU** (~4.5 h) |
| 9 **Predict** | Kaggle kernel | **Kaggle GPU** (~0.9 h) |
| 10 Evaluate | `make eval` | Local only; downloads distilbert (~265 MB) |

Do **not** load `Qwen2.5-3B-Instruct` locally — `src/train_qlora.py` refuses to without a
GPU and points you here. Real weights live on Kaggle only.

---

## 1. Environment

Requires **Python 3.12**. Do not use 3.14 — much of the ML stack has no wheels for it.
[`uv`](https://github.com/astral-sh/uv) is used to create the venv.

```sh
git clone <this-repo> && cd GenAI_IA1
make setup          # creates .venv, installs requirements.txt
make test lint      # 7 tests should pass, lint clean
make help           # lists every target
```

Dependencies are split by where they run:

| File | Scope |
|---|---|
| `requirements.txt` | Local work. Deliberately excludes torch. |
| `requirements-eval.txt` | Scoring metrics. Pulls torch (CPU is fine). |
| `requirements-train.txt` | Kaggle only. Do not install locally. |

For stage 10 you also need `make setup-eval`.

---

## 2. Credentials

### Gemini (stage 6 only)

Needed only to regenerate reference reports. Get a key at
<https://aistudio.google.com/apikey>, then:

```sh
cp .env.example .env
# edit .env and set:  GEMINI_API_KEY=...
```

`.env` is gitignored. The key is read by `src/generate_reports.py` and never logged or
written to any output file.

### Kaggle (stages 8–9 only)

Needed only to retrain. Generate a token at <https://www.kaggle.com/settings/api>
("Generate New Token"), then:

```sh
mkdir -p ~/.kaggle
printf '%s' 'PASTE_TOKEN_HERE' > ~/.kaggle/access_token
chmod 600 ~/.kaggle/access_token
```

The client resolves credentials in this order: `KAGGLE_API_TOKEN` env var →
`~/.kaggle/access_token` → `$KAGGLE_CONFIG_DIR/kaggle.json` → `~/.kaggle/kaggle.json`
(only if that directory already exists) → `~/.config/kaggle/kaggle.json`.

The Kaggle account must be **phone-verified** — GPU and internet access on kernels
require it, and it cannot be done through the API.

---

## 3. Regenerate the dataset (local)

```sh
make data       # VCDB + MITRE ATT&CK into data/raw/
make survey     # rewrites docs/DATA_SURVEY.md
make labels     # rewrites docs/LABEL_COVERAGE.md; validates every ATT&CK ID
make blobs      # selected.jsonl + blobs.jsonl  (runs `select` first)
make pilot      # the TEMPLATING_DESIGN.md §6 checks, incl. the leakage test
```

`make blobs` is deterministic: skeleton choice, entity names, and event ordering are all
seeded from each record's `incident_id`, so a rerun reproduces byte-identical blobs.

Expected at this point: 400 selected records, blobs at median 810 tokens (cap 850).

---

## 4. Regenerate reference reports (needs Gemini key)

```sh
make reports-pilot     # 20 reports first — inspect before committing to the rest
make reports           # the remaining 380; resumes from checkpoint
make stats             # rewrites docs/DATASET_STATS.md
make sft               # writes train.jsonl (360) and test.jsonl (40), token-checked
```

`generate_reports.py` throttles to 6 s between requests, honours the retry delay the API
returns on a 429, checkpoints every 5 reports, and logs failures to
`data/processed/report_failures.jsonl` rather than skipping silently. A killed run
resumes where it stopped.

The model is pinned to `gemini-3.1-flash-lite`. Do not "fix" this to `gemini-2.5-flash` —
that returns 404 on current keys, `gemini-3.5-flash` caps at 20 free-tier requests, and
`gemini-3.5-flash-lite` rejects the `thinking_budget=0` this script requires.

---

## 5. Retrain (needs Kaggle GPU)

Only if you want a new adapter. **The committed predictions make this optional.**

```sh
# 1. Package the data as a Kaggle Dataset
mkdir -p /tmp/ds/src
cp data/processed/train.jsonl data/processed/test.jsonl /tmp/ds/
cp src/__init__.py src/train_qlora.py src/generate_predictions.py /tmp/ds/src/
cat > /tmp/ds/dataset-metadata.json <<'JSON'
{"title": "sentry-sft-data-v1", "id": "<your-username>/sentry-sft-data-v1",
 "licenses": [{"name": "CC-BY-SA-4.0"}]}
JSON
.venv/bin/kaggle datasets create -p /tmp/ds --dir-mode zip

# 2. Push the training kernel
mkdir -p /tmp/k && cp notebooks/train_kaggle.ipynb /tmp/k/
cat > /tmp/k/kernel-metadata.json <<'JSON'
{"id": "<your-username>/sentry-qlora-train", "title": "Sentry QLoRA Train",
 "code_file": "train_kaggle.ipynb", "language": "python", "kernel_type": "notebook",
 "is_private": true, "enable_gpu": true, "enable_internet": true,
 "machine_shape": "NvidiaTeslaT4",
 "dataset_sources": ["<your-username>/sentry-sft-data-v1"],
 "competition_sources": [], "kernel_sources": [], "model_sources": []}
JSON
.venv/bin/kaggle kernels push -p /tmp/k
.venv/bin/kaggle kernels status <your-username>/sentry-qlora-train
```

**`machine_shape` must be `NvidiaTeslaT4`.** A P100 is `sm_60`, and the Kaggle image's
PyTorch supports only `sm_70` and above — a P100 run fails after burning a slot.

Licensing note: VCDB is CC BY-SA 4.0, so any derivative dataset you publish must carry a
compatible licence.

---

## 6. Regenerate predictions (needs Kaggle GPU)

Skip this — `data/processed/preds_base.jsonl` and `preds_tuned.jsonl` are committed.

To redo it, push `notebooks/predict_kaggle.ipynb` with the same metadata plus
`"kernel_sources": ["<your-username>/sentry-qlora-train"]` so the adapter is an input,
then download the outputs into `data/processed/`.

---

## 7. Evaluate (local)

```sh
make setup-eval        # adds rouge-score, bert-score, torch (CPU)
make eval              # rewrites docs/EVAL_RESULTS.md
```

This reads `test.jsonl` and the two prediction files, and needs no GPU. Runs in a few
minutes on CPU.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `make blobs` finds no records | `make data` not run, or VCDB's mixed `.json`/`.JSON` extensions — the loaders match case-insensitively; a custom script must too |
| Kernel reports COMPLETE but produces nothing | Notebook cells lack `id` fields; rebuild with the `nbformat` library, never hand-written JSON |
| `AssertionError: /kaggle/input/<slug> not found` | The private BYOD image mounts at `/kaggle/input/datasets/<owner>/<slug>`; the notebooks discover paths by search |
| `ImportError: incompatible version of torchao` | Kaggle image drift between `peft` and `torchao`; pin `transformers<6` and avoid `-U` on `peft` |
| `sm_60 is not compatible` | You drew a P100. Set `machine_shape` to `NvidiaTeslaT4` |
| Reports truncate mid-sentence | Gemini thinking consuming the output budget; `thinking_budget` must be 0 |
