"""
Single source of truth for paths and project constants.

The constants below mirror `docs/SCOPE.md`. Section 6 of that document declares
them non-negotiable, so they live in one module rather than being retyped into
each script -- if a value here disagrees with SCOPE.md, SCOPE.md wins and this
file is the bug.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent.parent

DATA = ROOT / "data"
RAW = DATA / "raw"
INTERIM = DATA / "interim"
PROCESSED = DATA / "processed"

VCDB_DIR = RAW / "vcdb" / "validated"
VCDB_SCHEMA_DIR = RAW / "vcdb" / "schema"
VCDB_MAPPING_DIR = RAW / "vcdb" / "mappings"
ATTACK_BUNDLE = RAW / "attack" / "enterprise-attack.json"

DOCS = ROOT / "docs"
NOTEBOOKS = ROOT / "notebooks"
OUTPUTS = ROOT / "outputs"

# ---------------------------------------------------------------------------
# Fixed constraints -- SCOPE.md section 6
# ---------------------------------------------------------------------------
BASE_MODEL = "Qwen/Qwen2.5-3B-Instruct"
QUANTIZATION = "4bit-nf4"
MAX_SEQ_LEN = 1536

N_TRAIN = 360
N_TEST = 40

# Input blob budget -- SCOPE.md section 2.7. Derived, not guessed:
#
#   1536  max_seq_len
#   - 560 report allowance (the SCOPE.md 3.7 reference report measures 451 with
#         the real Qwen2.5 tokenizer; 560 leaves p90 headroom)
#   - 106 system prompt
#   -  13 Qwen chat-template scaffolding (measured, not estimated)
#   = 857, rounded down
#
# The phase-1 figure of 700 came from a characters/3.6 heuristic and was wrong:
# structured telemetry tokenizes far worse than prose.
MAX_INPUT_TOKENS = 850
MAX_EVENT_ROWS = 12

# ---------------------------------------------------------------------------
# Output contract -- SCOPE.md section 3
# ---------------------------------------------------------------------------
SECTIONS = (
    "Summary",
    "Affected Assets",
    "Attack Technique",
    "Severity",
    "Root Cause",
    "Recommended Actions",
)

SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")

# SCOPE.md section 3.5: required verbatim when the telemetry does not support a
# root cause -- e.g. when truncation dropped `analyst_notes`.
NO_ROOT_CAUSE = "Insufficient evidence in the available telemetry to determine root cause."

# ---------------------------------------------------------------------------
# Reproducibility
# ---------------------------------------------------------------------------
SEED = 20260826


def ensure_dirs() -> None:
    """Create the writable directories a pipeline step may need."""
    for d in (RAW, INTERIM, PROCESSED, OUTPUTS):
        d.mkdir(parents=True, exist_ok=True)
