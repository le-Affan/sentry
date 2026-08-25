#!/usr/bin/env python3
"""
Select the VCDB records that will become training pairs.

Applies, in order:
  1. labels/technique_lookup.yaml   -- assign one ATT&CK technique per record
  2. labels/excluded_varieties.yaml -- drop out-of-scope categories
  3. a rare-class floor             -- classes below MIN_CLASS are dropped whole
  4. a per-class cap                -- no class may dominate the sample
  5. a quality preference           -- prefer records with a usable summary
  6. a stratified train/test split  -- every class present in both halves

Writes data/processed/selected.jsonl (one record per line) and prints the final
per-class counts. Does not render telemetry; see src/templater.py for that.
"""

import json
import sys
from collections import Counter, defaultdict

import yaml

from src import config as c
from src.label_coverage import load_attack_index, load_records, validate_lookup

LOOKUP = c.ROOT / "labels" / "technique_lookup.yaml"
EXCLUDED = c.ROOT / "labels" / "excluded_varieties.yaml"
OUT = c.PROCESSED / "selected.jsonl"

# Per-class cap. LABEL_COVERAGE.md section 4 derived 205 for a 1,000-pair target;
# at 400 pairs the apportionment step does the balancing, so the cap only needs to
# stop one class monopolising the candidate pool before apportionment runs.
CLASS_CAP = 205

# Classes below this are dropped entirely rather than included thinly. A class
# with four examples teaches nothing, cannot support a stratified split, and adds
# noise to per-class accuracy. LABEL_COVERAGE.md section 4 rule 1.
MIN_CLASS = 20

# Every surviving class must contribute at least this many records, so the
# 40-record test split is guaranteed a non-zero count for each.
MIN_PER_CLASS_IN_SAMPLE = 8

# Summary length band, in words. Below the minimum there is not enough narrative
# to derive a root cause; above the maximum the blob cannot fit its token budget
# without the truncation ladder discarding the notes entirely.
SUMMARY_MIN_WORDS = 20
SUMMARY_MAX_WORDS = 90
SUMMARY_IDEAL_WORDS = 45

TARGET = c.N_TRAIN + c.N_TEST
TEST_FRACTION = c.N_TEST / TARGET


def summary_words(rec):
    return len((rec.get("summary") or "").split())


def record_varieties(rec):
    out = []
    for cat, body in (rec.get("action") or {}).items():
        if isinstance(body, dict):
            for v in body.get("variety", []) or []:
                out.append(f"{cat}.{v}")
    return out


def assign_technique(rec, lut):
    """Highest-priority matching variety wins. See technique_lookup.yaml."""
    candidates = [lut[v] for v in record_varieties(rec) if v in lut]
    if not candidates:
        return None
    return max(candidates, key=lambda r: r["priority"])


def largest_remainder(counts, total, floor=None):
    """Apportion `total` across classes proportionally, without drift.

    Plain rounding of proportional shares does not sum to the target; the
    largest-remainder method fixes that deterministically.
    """
    pool = sum(counts.values())
    exact = {k: v / pool * total for k, v in counts.items()}
    alloc = {k: int(v) for k, v in exact.items()}

    # Respect the per-class floor before distributing what is left over.
    fl = MIN_PER_CLASS_IN_SAMPLE if floor is None else floor
    for k in alloc:
        alloc[k] = max(alloc[k], min(fl, counts[k]))

    while sum(alloc.values()) > total:
        # Trim from the largest class that is still above its floor.
        k = max(
            (k for k in alloc if alloc[k] > min(fl, counts[k])),
            key=lambda k: alloc[k],
            default=None,
        )
        if k is None:
            break
        alloc[k] -= 1

    remainders = sorted(exact, key=lambda k: exact[k] - int(exact[k]), reverse=True)
    i = 0
    while sum(alloc.values()) < total and remainders:
        k = remainders[i % len(remainders)]
        if alloc[k] < counts[k]:
            alloc[k] += 1
        i += 1
        if i > len(remainders) * 1000:
            break
    return alloc


def main():
    lut_doc = yaml.safe_load(LOOKUP.read_text(encoding="utf-8"))
    exc_doc = yaml.safe_load(EXCLUDED.read_text(encoding="utf-8"))
    lut = {r["veris_path"]: r for r in lut_doc["techniques"]}
    excluded_cats = {e["category"] for e in exc_doc["excluded_categories"]}

    problems = validate_lookup(lut_doc["techniques"], load_attack_index())
    if problems:
        sys.exit("lookup validation failed:\n  " + "\n  ".join(problems))

    records = load_records()
    print(f"loaded {len(records):,} VCDB records", file=sys.stderr)

    # VCDB reuses incident_id across 36 separate record files. Left alone, the
    # same id can be selected twice under *different* techniques, which puts a
    # contradictory label into the corpus and silently collapses downstream
    # where blobs are keyed by id. Keep the first occurrence of each.
    seen_ids, deduped = set(), []
    for rec in records:
        iid = rec.get("incident_id")
        if iid in seen_ids:
            continue
        seen_ids.add(iid)
        deduped.append(rec)
    n_dupes = len(records) - len(deduped)
    records = deduped
    if n_dupes:
        print(f"dropped {n_dupes} records with duplicate incident_id", file=sys.stderr)

    # --- step 1-2: label ---------------------------------------------------
    by_tech = defaultdict(list)
    dropped = Counter()
    for rec in records:
        cats = set((rec.get("action") or {}).keys())
        if cats and cats <= excluded_cats:
            dropped["excluded_category"] += 1
            continue
        tech = assign_technique(rec, lut)
        if tech is None:
            dropped["no_curated_variety"] += 1
            continue
        by_tech[(tech["attack_id"], tech["attack_name"])].append((rec, tech))

    labelled_total = sum(len(v) for v in by_tech.values())

    # --- step 3: rare-class floor -----------------------------------------
    rare = {k: len(v) for k, v in by_tech.items() if len(v) < MIN_CLASS}
    for k in rare:
        dropped["rare_class"] += len(by_tech[k])
        del by_tech[k]

    # --- step 4-5: cap, preferring records with a usable summary ----------
    capped = {}
    for k, items in by_tech.items():
        # analyst_notes is condensed from the VCDB summary, and it is usually the
        # only field that makes Root Cause derivable (SCOPE.md 2.9). But summaries
        # run to 2,826 words, and a long one blows the ~700-token blob budget and
        # forces the truncation ladder all the way to dropping the notes -- losing
        # exactly what we selected for. So prefer summaries inside a usable band
        # rather than the longest available. Ties broken by incident_id, so the
        # selection is deterministic.
        ranked = sorted(
            items,
            key=lambda it: (
                not (SUMMARY_MIN_WORDS <= summary_words(it[0]) <= SUMMARY_MAX_WORDS),
                abs(summary_words(it[0]) - SUMMARY_IDEAL_WORDS),
                it[0].get("incident_id", ""),
            ),
        )
        capped[k] = ranked[:CLASS_CAP]

    capped_counts = {k: len(v) for k, v in capped.items()}
    capped_total = sum(capped_counts.values())

    # --- step 6: apportion to TARGET, then stratified split ---------------
    alloc = largest_remainder(capped_counts, TARGET)

    # Apportion the test split globally rather than rounding each class
    # independently -- per-class rounding drifts off the N_TEST target.
    test_alloc = largest_remainder({k: alloc[k] for k in alloc}, c.N_TEST, floor=1)
    test_alloc = {k: max(1, min(v, alloc[k])) for k, v in test_alloc.items()}
    while sum(test_alloc.values()) > c.N_TEST:
        k = max(test_alloc, key=lambda k: test_alloc[k])
        if test_alloc[k] <= 1:
            break
        test_alloc[k] -= 1

    selected = []
    for k, n in alloc.items():
        chosen = capped[k][:n]
        n_test = test_alloc[k]

        # `chosen` is ordered by descending summary length, so slicing the head
        # into test would make the test set systematically the richest records.
        # Take an evenly spaced stride instead.
        # Offset to the centre of each stride bucket; starting at index 0 would
        # put the single longest-summary record of every class into test.
        stride = n / n_test
        test_idx = {min(n - 1, int((i + 0.5) * stride)) for i in range(n_test)}

        for i, (rec, tech) in enumerate(chosen):
            selected.append(
                {
                    "incident_id": rec.get("incident_id"),
                    "attack_id": tech["attack_id"],
                    "attack_name": tech["attack_name"],
                    "veris_path": tech["veris_path"],
                    "confidence": tech["confidence"],
                    "summary_words": summary_words(rec),
                    "split": "test" if i in test_idx else "train",
                }
            )

    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", encoding="utf-8") as fh:
        for row in selected:
            fh.write(json.dumps(row) + "\n")

    # --- report ------------------------------------------------------------
    split_counts = Counter(s["split"] for s in selected)
    print()
    print(f"labelled pool             : {labelled_total:,}")
    for k, v in dropped.most_common():
        print(f"  dropped, {k:<22}: {v:,}")
    if rare:
        print(
            f"  rare classes dropped (<{MIN_CLASS}): "
            + ", ".join(f"{k[0]} ({n})" for k, n in sorted(rare.items(), key=lambda x: x[1]))
        )
    print(f"after cap of {CLASS_CAP}          : {capped_total:,}")
    print(
        f"selected                  : {len(selected):,} "
        f"({split_counts['train']} train / {split_counts['test']} test)"
    )
    print()

    print(f"{'technique':<12} {'name':<38} {'n':>5} {'train':>6} {'test':>5} {'share':>7}")
    print("-" * 78)
    per = Counter((s["attack_id"], s["attack_name"]) for s in selected)
    for (aid, aname), n in per.most_common():
        tr = sum(1 for s in selected if s["attack_id"] == aid and s["split"] == "train")
        te = sum(1 for s in selected if s["attack_id"] == aid and s["split"] == "test")
        share = 100.0 * n / len(selected)
        print(f"{aid:<12} {aname[:38]:<38} {n:>5} {tr:>6} {te:>5} {share:>6.1f}%")
    print("-" * 78)
    print(f"{'TOTAL':<51} {len(selected):>5} {split_counts['train']:>6} {split_counts['test']:>5}")
    print()
    print(f"largest class share: {100.0 * per.most_common(1)[0][1] / len(selected):.1f}%")
    print(f"wrote {OUT}", file=sys.stderr)


if __name__ == "__main__":
    main()
