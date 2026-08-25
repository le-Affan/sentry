#!/usr/bin/env python3
"""
Pilot check from docs/TEMPLATING_DESIGN.md section 6.

The test that matters is 6.3: can a trivial classifier recover the technique from
event STRUCTURE alone, with all description text removed? If it can, the templater
leaks the label and a fine-tuned model could score well on technique accuracy
without reading the telemetry -- meaning the metric measures our generator.

Also reports the section 6.1/6.2/6.4 checks: skeleton uniformity, event-count
overlap, and noise survival.

Baseline note: 46.3% is the majority share of the *uncapped* label pool
(LABEL_COVERAGE.md section 3). The corpus actually sampled is capped at 205 per
class, so its majority share is ~17.4%. The capped figure is the honest baseline
for this test, and both are printed.
"""

import json
import sys
from collections import Counter

from sklearn.dummy import DummyClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score
from sklearn.pipeline import make_pipeline

from src import config as c

BLOBS = c.PROCESSED / "blobs.jsonl"


def event_types_from_blob(blob):
    """The event_type column only. Descriptions and every entity are discarded."""
    out = []
    for line in blob.split("\n"):
        parts = [p.strip() for p in line.split(" | ")]
        if len(parts) >= 8 and parts[0].isdigit():
            out.append(parts[6])
    return out


def main(pilot_n=None):
    rows = [json.loads(x) for x in BLOBS.read_text(encoding="utf-8").splitlines()]
    rows = [r for r in rows if r["blob"]]
    if pilot_n:
        # Stratified pilot slice, so every technique is represented.
        by_t = {}
        for r in rows:
            by_t.setdefault(r["technique"], []).append(r)
        per = max(1, pilot_n // len(by_t))
        rows = [r for v in by_t.values() for r in v[:per]]

    X = [" ".join(event_types_from_blob(r["blob"])) for r in rows]
    y = [r["technique"] for r in rows]
    dist = Counter(y)
    majority = max(dist.values()) / len(y)

    print(f"pilot corpus            : {len(rows)} blobs, {len(dist)} techniques")
    print(
        f"majority-class baseline : {100 * majority:.1f}%  "
        f"({dist.most_common(1)[0][0]}, capped corpus)"
    )
    print("uncapped pool baseline  : 46.3%  (LABEL_COVERAGE.md, for reference only)")
    print()

    # --- 6.3 leakage test --------------------------------------------------
    pipe = make_pipeline(
        CountVectorizer(analyzer="word", token_pattern=r"\S+", ngram_range=(1, 3)),
        LogisticRegression(max_iter=2000, class_weight="balanced"),
    )
    folds = min(5, min(dist.values()))
    if folds < 2:
        sys.exit("a technique has too few blobs to cross-validate")
    acc = cross_val_score(pipe, X, y, cv=folds, scoring="accuracy")
    dummy = cross_val_score(
        DummyClassifier(strategy="most_frequent"), X, y, cv=folds, scoring="accuracy"
    )

    print("LEAKAGE TEST (TEMPLATING_DESIGN.md 6.3)")
    print("  bag of event_type 1-3 grams, descriptions and entities stripped")
    print(f"  classifier accuracy   : {acc.mean() * 100:.1f}%  (+/- {acc.std() * 100:.1f})")
    print(f"  majority baseline     : {dummy.mean() * 100:.1f}%")
    lift = acc.mean() - dummy.mean()
    print(f"  lift over baseline    : {lift * 100:+.1f} points")
    verdict = (
        "PASS -- structure alone is close to uninformative"
        if lift < 0.15
        else "MARGINAL -- structure carries some signal"
        if lift < 0.35
        else "FAIL -- event structure leaks the technique label"
    )
    print(f"  verdict               : {verdict}")
    print()

    # --- 6.1 skeleton uniformity ------------------------------------------
    print("SKELETON UNIFORMITY (6.1: no skeleton over 40% within its technique)")
    per_t = {}
    for r in rows:
        per_t.setdefault(r["technique"], Counter())[r["skeleton"]] += 1
    worst = []
    for t, cnt in sorted(per_t.items()):
        tot = sum(cnt.values())
        sk, n = cnt.most_common(1)[0]
        share = n / tot
        flag = "  <-- over" if share > 0.40 else ""
        worst.append((t, share))
        print(f"  {t:12s} {len(cnt)} skeletons, top {100 * share:5.1f}% ({sk}){flag}")
    print()

    # --- 6.2 event-count overlap ------------------------------------------
    print("EVENT-COUNT OVERLAP (6.2: no technique separable by length alone)")
    lens = {}
    for r in rows:
        lens.setdefault(r["technique"], []).append(len(event_types_from_blob(r["blob"])))
    for t in sorted(lens):
        v = sorted(lens[t])
        print(f"  {t:12s} min {v[0]}  median {v[len(v) // 2]}  max {v[-1]}")
    # Pair each technique with its own range explicitly; zipping a list of ranges
    # against the dict's keys relies on iteration order lining up by accident.
    ranges = {t: (min(v), max(v)) for t, v in lens.items()}
    disjoint = [
        t
        for t, (lo, hi) in ranges.items()
        if all(hi < lo2 or lo > hi2 for t2, (lo2, hi2) in ranges.items() if t2 != t)
    ]
    print(f"  techniques separable by length alone: {disjoint or 'none'}")
    print()

    # --- 6.4 noise survival ------------------------------------------------
    survived = sum(1 for r in rows if r["n_noise"] > 0)
    print("NOISE SURVIVAL (6.4: benign events in >=90% of blobs after truncation)")
    print(f"  blobs generated with noise: {100 * survived / len(rows):.1f}%")
    print("  NOTE: n_noise is counted before the truncation ladder runs; the ladder")
    print("  drops middle events, so surviving noise is lower. See the caveat in the")
    print("  report -- this check is only meaningful once blobs fit without truncation.")


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else None)
