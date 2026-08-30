"""Guard the constants that SCOPE.md declares non-negotiable.

These are cheap assertions, but they catch the failure mode that matters:
someone quietly changing a fixed constraint mid-project.
"""

from src import config as c


def test_fixed_constraints_match_scope():
    assert c.BASE_MODEL == "Qwen/Qwen2.5-3B-Instruct"
    # Raised from 1024 in phase 3c: the SCOPE.md 3.7 reference report measures
    # 451 real Qwen tokens, which left no workable blob budget at 1024.
    assert c.MAX_SEQ_LEN == 1536
    assert c.N_TRAIN == 360
    assert c.N_TEST == 40


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


def test_technique_lookup_is_valid():
    """Every curated technique ID must exist and be current in the pinned bundle.

    A revoked ID here becomes a wrong reference answer in every training pair
    that uses it, so this guards the labelling artifact directly.
    """
    import pytest

    if not c.ATTACK_BUNDLE.exists():
        pytest.skip("ATT&CK bundle not downloaded; run `make data`")

    import yaml
    from src.label_coverage import load_attack_index, validate_lookup

    rows = yaml.safe_load((c.ROOT / "labels" / "technique_lookup.yaml").read_text())["techniques"]
    assert validate_lookup(rows, load_attack_index()) == []


def test_lookup_and_exclusions_do_not_overlap():
    import yaml

    lut = yaml.safe_load((c.ROOT / "labels" / "technique_lookup.yaml").read_text())
    exc = yaml.safe_load((c.ROOT / "labels" / "excluded_varieties.yaml").read_text())

    labelled = {r["veris_path"] for r in lut["techniques"]}
    excluded = {e["veris_path"] for e in exc["excluded_varieties"]}
    deferred = {d["veris_path"] for d in exc["deferred"]}

    assert not (labelled & excluded), "a variety is both labelled and excluded"
    assert not (labelled & deferred), "a variety is both labelled and deferred"


def test_lookup_confidence_values_are_known():
    import yaml

    rows = yaml.safe_load((c.ROOT / "labels" / "technique_lookup.yaml").read_text())["techniques"]
    for r in rows:
        assert r["confidence"] in ("high", "medium", "low"), r["veris_path"]
        assert r["attack_id"].startswith("T"), r["veris_path"]
        assert r["rationale"].strip(), r["veris_path"]


def test_demo_blurbs_are_grounded_in_their_skeletons():
    """Every demo catalog blurb must trace to its own chain's nodes.

    Guards the failure mode that inspection misses: copy that sounds plausible
    but describes something the chain never does. See src/check_blurbs.py.
    """
    from src.check_blurbs import main

    assert main(verbose=False) == 0, "ungrounded blurb copy -- run `make blurbs`"
