#!/usr/bin/env python3
"""
Local demo API for Sentry.

Serves the scenario catalog and returns the six-section incident report for a
chosen scenario, parsed into structured sections as well as raw Markdown.

INFERENCE MODE
--------------
Reports come from `data/processed/preds_tuned.jsonl` -- real output from the
fine-tuned adapter, generated on a Kaggle Tesla T4 (kernel
`l0affan/sentry-qlora-predict`) and committed to this repository. They are not
mocked or hand-written.

Live local inference is deliberately not implemented. The 3B base model plus
adapter needs a GPU this machine does not have; on CPU a single report takes
minutes, and `outputs/qlora-adapter/` is empty because the adapter lives in the
Kaggle kernel output. A custom pasted blob therefore returns HTTP 501 with an
explanation rather than a wrong or fabricated answer. See docs/REPRODUCE.md.

Run:
    make demo          # or: .venv/bin/uvicorn src.demo_api:app --port 8000
    open http://127.0.0.1:8000
"""

import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from src import config as c
from src.scenarios import build_catalog, grouped_catalog

STATIC = c.ROOT / "demo"

INFERENCE_MODE = "precomputed"
INFERENCE_NOTE = (
    "Reports are real fine-tuned-model output, generated on a Kaggle Tesla T4 and "
    "committed to this repository. This machine has no GPU, so live inference on a "
    "custom blob is unavailable locally."
)

SECTION_ORDER = [
    "Summary",
    "Affected Assets",
    "Attack Technique",
    "Severity",
    "Root Cause",
    "Recommended Actions",
]
SECTION_RE = re.compile(r"^##\s+(?P<name>.+?)\s*$", re.M)

app = FastAPI(title="Sentry demo", version="1.0")

_catalog: dict[str, dict] = {}
_groups: list[dict] = []


@app.on_event("startup")
def load_catalog() -> None:
    """Load the corpus once at startup, not per request."""
    global _catalog, _groups
    scenarios = build_catalog()
    _catalog = {s["id"]: s for s in scenarios}
    _groups = grouped_catalog()
    print(f"[sentry] loaded {len(_catalog)} scenarios, mode={INFERENCE_MODE}")


def split_sections(report: str) -> dict[str, str]:
    """Split a report into {heading: body}. Missing headings are simply absent."""
    matches = list(SECTION_RE.finditer(report))
    out = {}
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(report)
        out[m.group("name")] = report[m.end() : end].strip()
    return out


def report_payload(scenario: dict) -> dict:
    report = scenario.get("prediction")
    if not report:
        raise HTTPException(
            status_code=503,
            detail=f"No stored prediction for scenario {scenario['id']}.",
        )
    sections = split_sections(report)
    return {
        "scenario_id": scenario["id"],
        "technique_id": scenario["technique_id"],
        "inference_mode": INFERENCE_MODE,
        "report_markdown": report,
        "sections": [
            {"heading": h, "body": sections.get(h, "")} for h in SECTION_ORDER if h in sections
        ],
        "missing_sections": [h for h in SECTION_ORDER if h not in sections],
        "reference_markdown": scenario["reference"],
    }


class AnalyzeRequest(BaseModel):
    scenario_id: str | None = None
    blob: str | None = None


@app.get("/api/meta")
def meta() -> dict:
    return {
        "inference_mode": INFERENCE_MODE,
        "note": INFERENCE_NOTE,
        "model": c.BASE_MODEL,
        "adapter": "QLoRA r=16, trained on Kaggle Tesla T4",
        "scenario_count": len(_catalog),
    }


@app.get("/api/scenarios")
def scenarios() -> dict:
    """The full catalog, grouped by technique. Blob text included."""
    return {
        "count": len(_catalog),
        "groups": [
            {
                "technique_id": g["technique_id"],
                "technique_name": g["technique_name"],
                "scenarios": [
                    {
                        k: s[k]
                        for k in (
                            "id",
                            "technique_id",
                            "technique_name",
                            "descriptor",
                            "label",
                            "description",
                            "card_title",
                            "card_blurb",
                            "has_plain_copy",
                            "severity",
                            "asset_roles",
                            "asset_hosts",
                            "blob",
                            "blob_tokens",
                        )
                    }
                    for s in g["scenarios"]
                ],
            }
            for g in _groups
        ],
    }


@app.get("/api/scenarios/{scenario_id}")
def scenario(scenario_id: str) -> dict:
    s = _catalog.get(scenario_id)
    if s is None:
        raise HTTPException(status_code=404, detail=f"Unknown scenario: {scenario_id}")
    return s


@app.post("/api/analyze")
def analyze(req: AnalyzeRequest) -> dict:
    if not req.scenario_id and not req.blob:
        raise HTTPException(status_code=400, detail="Provide either scenario_id or blob.")

    if req.scenario_id:
        s = _catalog.get(req.scenario_id)
        if s is None:
            raise HTTPException(status_code=404, detail=f"Unknown scenario: {req.scenario_id}")
        # An unmodified blob for a known scenario resolves to its stored report.
        if req.blob and req.blob.strip() != s["blob"].strip():
            raise HTTPException(
                status_code=501,
                detail=(
                    "The telemetry was edited, so this is a new incident. "
                    + INFERENCE_NOTE
                    + " Reset the panel to the original scenario text to analyze it."
                ),
            )
        return report_payload(s)

    # A pasted blob that exactly matches a known scenario is still answerable.
    pasted = req.blob.strip()
    for s in _catalog.values():
        if s["blob"].strip() == pasted:
            return report_payload(s)

    raise HTTPException(status_code=501, detail=INFERENCE_NOTE)


if STATIC.is_dir():
    app.mount("/static", StaticFiles(directory=STATIC), name="static")

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")
