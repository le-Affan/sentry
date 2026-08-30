#!/usr/bin/env python3
"""
Enforce that every demo catalog blurb is grounded in its own chain skeleton.

THE RULE
    Every content word in a `card_blurb` must be covered by a `card_blurb_trace`
    entry mapping a phrase to a field of that SAME skeleton -- a node `ref`, or
    the skeleton's `name` or `notes`. Deleting all traced phrases from the blurb
    must leave only function words from FUNCTION_WORDS below.

Anything left over is an ungrounded claim: a phrase describing something the
chain does not actually do. The check fails rather than letting it through,
because the failure mode it guards against -- plausible-sounding copy that no
event supports -- is invisible on inspection.

Run directly for a full trace report, or via `make test` / `make lint` as a
hard gate:

    python -m src.check_blurbs          # report every trace, exit 1 on failure
"""

import re
import sys

import yaml

from src import config as c

CHAINS = c.ROOT / "src" / "chains.yaml"

# Words that may remain after traced phrases are removed. Deliberately closed:
# articles, prepositions, conjunctions, auxiliaries, pronouns, determiners.
# No nouns, no domain verbs. Extend only with genuine function words.
FUNCTION_WORDS = {
    "a",
    "an",
    "the",
    "and",
    "or",
    "but",
    "so",
    "then",
    "than",
    "that",
    "which",
    "who",
    "whose",
    "it",
    "its",
    "this",
    "these",
    "those",
    "their",
    "them",
    "they",
    "of",
    "to",
    "from",
    "on",
    "in",
    "into",
    "onto",
    "at",
    "by",
    "for",
    "with",
    "without",
    "across",
    "after",
    "before",
    "during",
    "until",
    "while",
    "over",
    "under",
    "up",
    "down",
    "out",
    "off",
    "as",
    "about",
    "against",
    "between",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "being",
    "has",
    "have",
    "had",
    "do",
    "does",
    "did",
    "can",
    "could",
    "will",
    "would",
    "may",
    "might",
    "must",
    "not",
    "no",
    "nor",
    "only",
    "also",
    "again",
    "later",
    "more",
    "most",
    "much",
    "one",
    "two",
    "both",
    "all",
    "any",
    "each",
    "every",
    "some",
    "another",
    "there",
    "here",
    "when",
    "where",
    "how",
    "why",
    "if",
    "because",
    # light connective verbs that carry no domain claim on their own
    "used",
    "caused",
    "let",
    "made",
    "came",
    "got",
    "led",
    "pushed",
    "engaged",
    "reached",
    "turned",
    "appeared",
    "started",
    "opened",
    "wrote",
    "read",
}

WORD_RE = re.compile(r"[A-Za-z][A-Za-z'\-]*")


def skeleton_fields(sk: dict) -> set[str]:
    """Valid trace targets for one skeleton: node refs plus name/notes."""
    refs = {n["ref"] for n in sk["nodes"]}
    for extra in ("name", "notes"):
        if sk.get(extra):
            refs.add(extra)
    return refs


def check_skeleton(sk: dict) -> tuple[list[str], list[tuple[str, str, str]]]:
    """Return (problems, trace_rows) for one skeleton."""
    problems: list[str] = []
    rows: list[tuple[str, str, str]] = []

    blurb = sk.get("card_blurb")
    trace = sk.get("card_blurb_trace")
    if not blurb:
        return problems, rows
    if not trace:
        return [f"{sk['id']}: has card_blurb but no card_blurb_trace"], rows

    valid = skeleton_fields(sk)
    node_text = {n["ref"]: n["desc"] for n in sk["nodes"]}
    node_text["name"] = sk.get("name", "")
    node_text["notes"] = sk.get("notes", "")

    residue = blurb
    for phrase, target in trace.items():
        if phrase not in blurb:
            problems.append(f"{sk['id']}: traced phrase not in blurb: {phrase!r}")
            continue
        if target not in valid:
            problems.append(
                f"{sk['id']}: phrase {phrase!r} traces to {target!r}, "
                f"which is not a node/field of this skeleton (valid: {sorted(valid)})"
            )
            continue
        residue = residue.replace(phrase, " ")
        rows.append((phrase, target, node_text[target]))

    leftover = sorted({w.lower() for w in WORD_RE.findall(residue)} - FUNCTION_WORDS)
    if leftover:
        problems.append(
            f"{sk['id']}: UNGROUNDED word(s) {leftover} -- every content word must "
            f"be covered by a card_blurb_trace entry, or removed from the blurb"
        )
    return problems, rows


def main(verbose: bool = True) -> int:
    chains = yaml.safe_load(CHAINS.read_text(encoding="utf-8"))
    all_problems: list[str] = []
    checked = 0

    for sk in chains["skeletons"]:
        if not sk.get("card_blurb"):
            continue
        checked += 1
        problems, rows = check_skeleton(sk)
        all_problems += problems
        if verbose:
            status = "FAIL" if problems else "ok"
            print(f"\n[{status}] {sk['id']} — {sk['name']}")
            print(f"  blurb: {sk['card_blurb']}")
            for phrase, target, text in rows:
                print(f"    {phrase!r}")
                print(f"        <- {target}: {text}")
            for p in problems:
                print(f"    !! {p}")

    print(f"\n{checked} blurb(s) checked, {len(all_problems)} problem(s)")
    if all_problems:
        print("\nPROBLEMS:")
        for p in all_problems:
            print(f"  {p}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(verbose="--quiet" not in sys.argv))
