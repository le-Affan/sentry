"""Guard the constants that SCOPE.md declares non-negotiable.

These are cheap assertions, but they catch the failure mode that matters:
someone quietly changing a fixed constraint mid-project.
"""

from src import config as c


def test_fixed_constraints_match_scope():
    assert c.BASE_MODEL == "Qwen/Qwen2.5-3B-Instruct"
    assert c.MAX_SEQ_LEN == 1024
    assert c.N_TRAIN == 900
    assert c.N_TEST == 100


def test_input_budget_leaves_room_for_output():
    # SCOPE.md 2.7: the blob is capped so input + report fit one sequence.
    assert c.MAX_INPUT_TOKENS < c.MAX_SEQ_LEN


def test_output_contract():
    assert c.SECTIONS == (
        "Summary",
        "Affected Assets",
        "Attack Technique",
        "Severity",
        "Root Cause",
        "Recommended Actions",
    )
    assert c.SEVERITY_LEVELS == ("Low", "Medium", "High", "Critical")


def test_scope_doc_declares_the_same_headings():
    """The docs and the code must not drift apart."""
    scope = (c.DOCS / "SCOPE.md").read_text(encoding="utf-8")
    for section in c.SECTIONS:
        assert f"`## {section}`" in scope or f"## {section}" in scope
    for level in c.SEVERITY_LEVELS:
        assert level in scope

