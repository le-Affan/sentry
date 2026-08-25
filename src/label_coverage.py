#!/usr/bin/env python3
"""
Apply labels/technique_lookup.yaml to every VCDB record and report coverage.

Answers three questions before any dataset is built:
  1. How many records can we actually label, and how many are lost to exclusion
     or to varieties we never curated?
  2. Are the technique IDs in the lookup real, current, and correctly named?
     ATT&CK revokes techniques between versions -- T1562 is revoked in 19.x --
     so an unvalidated lookup silently produces dead labels.
  3. Is the label distribution balanced enough to sample ~1,000 pairs from?

Prints a report to stdout and writes docs/LABEL_COVERAGE.md.
Read-only with respect to data/ and labels/.
"""

import json
import sys
from collections import Counter

import yaml

from src import config as c

LOOKUP = c.ROOT / "labels" / "technique_lookup.yaml"
EXCLUDED = c.ROOT / "labels" / "excluded_varieties.yaml"
OUT_MD = c.DOCS / "LABEL_COVERAGE.md"

# Target dataset size from SCOPE.md section 6.
TARGET_PAIRS = c.N_TRAIN + c.N_TEST

# A class holding more than this share of the sample is treated as dominant.
DOMINANCE_THRESHOLD = 0.25

# The capped pool must exceed the target by this factor. Records are still lost
# downstream to the ~700-token input budget (SCOPE.md 2.7) and to missing
# summaries, so a pool that only just reaches 1,000 leaves no slack.
HEADROOM = 1.20


def load_records():
    """VCDB mixes .json and .JSON extensions; match case-insensitively."""
    files = sorted(f for f in c.VCDB_DIR.glob("*") if f.suffix.lower() == ".json")
    if not files:
        sys.exit(f"no records under {c.VCDB_DIR} -- run `make data` first")
    return [json.loads(f.read_text(encoding="utf-8")) for f in files]


def load_attack_index():
    """Map ATT&CK ID -> (name, revoked, deprecated) from the pinned bundle."""
    bundle = json.loads(c.ATTACK_BUNDLE.read_text(encoding="utf-8"))
    idx = {}
    for o in bundle.get("objects", []):
        if o.get("type") != "attack-pattern":
            continue
        for ref in o.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                idx[ref["external_id"]] = (
                    o.get("name"),
                    bool(o.get("revoked")),
                    bool(o.get("x_mitre_deprecated")),
                )
    return idx


def validate_lookup(rows, attack_idx):
    """Fail loudly on IDs that are unknown, revoked, deprecated, or misnamed.

    A wrong name here becomes a wrong reference answer in every training pair
    that uses it, so this is a hard failure rather than a warning.
    """
    problems = []
    for row in rows:
        aid, aname = row["attack_id"], row["attack_name"]
        entry = attack_idx.get(aid)
        if entry is None:
            problems.append(f"{row['veris_path']}: {aid} is not in the ATT&CK bundle")
            continue
        name, revoked, deprecated = entry
        if revoked:
            problems.append(f"{row['veris_path']}: {aid} is REVOKED in this ATT&CK version")
        if deprecated:
            problems.append(f"{row['veris_path']}: {aid} is DEPRECATED")
        if name != aname:
            problems.append(f"{row['veris_path']}: {aid} name is {name!r}, lookup says {aname!r}")
    return problems


def record_varieties(rec):
    """All `<category>.<variety>` action paths on a record."""
    out = []
    for cat, body in (rec.get("action") or {}).items():
        if isinstance(body, dict):
            for v in body.get("variety", []) or []:
                out.append(f"{cat}.{v}")
    return out


def label_record(rec, lut, excluded_cats):
    """Assign one technique to a record.

    Returns (status, detail). Status is one of:
      labelled  -- at least one variety is in the lookup; highest priority wins
      excluded  -- every action category is one we deliberately dropped
      uncovered -- an in-scope category, but no variety we curated
    """
    cats = set((rec.get("action") or {}).keys())
    varieties = record_varieties(rec)

    candidates = [lut[v] for v in varieties if v in lut]
    if candidates:
        winner = max(candidates, key=lambda r: r["priority"])
        return "labelled", winner

    if cats and cats <= excluded_cats:
        return "excluded", None
    return "uncovered", varieties


def propose_cap(dist, target):
    """Smallest per-class cap that keeps the sample balanced and large enough.

    Sweeps candidate caps and picks the one whose resulting sample both reaches
    the target size and puts no single class above DOMINANCE_THRESHOLD.
    """
    needed = int(target * HEADROOM)
    for cap in range(10, max(dist.values()) + 1, 5):
        total = sum(min(n, cap) for n in dist.values())
        top = max(min(n, cap) for n in dist.values())
        if total >= needed and top / total <= DOMINANCE_THRESHOLD:
            return cap, total, top / total
    return None


def build_markdown(stats, dist, problems, cap, lut_rows):
    n = stats["total"]
    lab = stats["labelled"]
    L = []
    W = L.append

    W("# LABEL COVERAGE")
    W("")
    W("Generated by `src/label_coverage.py`. Applies `labels/technique_lookup.yaml` to")
    W("every VCDB record. These are **our** labels, not the official VERIS→ATT&CK")
    W("crosswalk — see that file's header and `DATA_SURVEY.md` §3.3 for why.")
    W("")
    W("---")
    W("")

    W("## 1. Lookup validation")
    W("")
    W(
        f"Technique IDs checked against the pinned ATT&CK bundle "
        f"(Enterprise {stats['attack_version']})."
    )
    W("")
    if problems:
        W(f"**{len(problems)} problem(s) found:**")
        W("")
        for p in problems:
            W(f"- {p}")
    else:
        W(f"All {len(lut_rows)} lookup rows validate: every ID exists, none are revoked or")
        W("deprecated, and every name matches the canonical ATT&CK name.")
    W("")

    W("## 2. Coverage")
    W("")
    W("| Outcome | Records | % of VCDB |")
    W("|---|---|---|")
    for key, label in (
        ("labelled", "**Labelled** — a curated variety matched"),
        ("excluded", "**Excluded** — category has no ATT&CK equivalent"),
        ("uncovered", "**Uncovered** — in-scope category, no curated variety"),
    ):
        W(f"| {label} | {stats[key]:,} | {100.0 * stats[key] / n:.1f}% |")
    W(f"| Total | {n:,} | 100.0% |")
    W("")
    W(
        f"The labelled pool is **{lab:,} records** against a target of {TARGET_PAIRS:,} "
        f"pairs — a {lab / TARGET_PAIRS:.1f}× surplus, so the dataset can be sampled"
    )
    W("selectively rather than scraped together.")
    W("")

    W("### 2.1 Coverage of the cyber-relevant pool")
    W("")
    W("Coverage against all of VCDB understates the result, because most of VCDB is")
    W("out of scope by design. The meaningful denominators:")
    W("")
    W("| Denominator | Records | Labelled | Coverage |")
    W("|---|---|---|---|")
    W(f"| All VCDB | {n:,} | {lab:,} | {100.0 * lab / n:.1f}% |")
    W(
        f"| Has a hacking/malware/social action | {stats['cyber_pool']:,} | {lab:,} | "
        f"{100.0 * lab / stats['cyber_pool']:.1f}% |"
    )
    W(
        f"| …and at least one named (non-Unknown/Other) variety | {stats['nameable']:,} | "
        f"{lab:,} | {100.0 * lab / stats['nameable']:.1f}% |"
    )
    W("")
    W(
        f"**{stats['cyber_pool'] - stats['nameable']:,} records "
        f"({100.0 * (stats['cyber_pool'] - stats['nameable']) / stats['cyber_pool']:.1f}% "
        f"of the cyber pool) record only `Unknown` or `Other`** as the action variety."
    )
    W("No lookup can label these — VERIS states that *something* happened without")
    W("stating what. They set a hard ceiling on any variety-based labelling scheme.")
    W("")

    W("### 2.2 What remains uncovered")
    W("")
    if stats["uncovered_top"]:
        W("| Uncovered variety | Records |")
        W("|---|---|")
        for v, cnt in stats["uncovered_top"]:
            W(f"| `{v}` | {cnt:,} |")
        W("")
        W("Varieties listed under `deferred` in `labels/excluded_varieties.yaml` are here")
        W("by choice — each is too rare to move coverage. `Unknown` and `Other` are")
        W("unlabellable in principle.")
    W("")

    W("## 3. Label distribution")
    W("")
    W("| # | Technique | Name | Records | % of labelled |")
    W("|---|---|---|---|---|")
    for i, ((aid, aname), cnt) in enumerate(dist.most_common(), 1):
        W(f"| {i} | `{aid}` | {aname} | {cnt:,} | {100.0 * cnt / lab:.1f}% |")
    W("")
    W(f"{len(dist)} distinct techniques.")
    W("")

    W("## 4. Class balance risk")
    W("")
    (top_id, top_name), top_n = dist.most_common(1)[0]
    top_share = top_n / lab
    counts = sorted(dist.values(), reverse=True)
    head3 = sum(counts[:3]) / lab
    tail = [k for k, v in dist.items() if v < 20]

    if top_share > DOMINANCE_THRESHOLD:
        W(f"**The distribution is dominated by one class.** `{top_id}` ({top_name}) accounts")
        W(f"for **{top_n:,} of {lab:,} labelled records ({100.0 * top_share:.1f}%)**. The top")
        W(f"three techniques together account for {100.0 * head3:.1f}%.")
    else:
        W(
            f"No single class dominates: the largest, `{top_id}` ({top_name}), holds "
            f"{100.0 * top_share:.1f}% of the labelled pool."
        )
    W("")
    W(f"The tail is thin as well — {len(tail)} of {len(dist)} techniques have fewer than 20")
    W("records:")
    W("")
    for k in sorted(tail, key=lambda x: dist[x]):
        W(f"- `{k[0]}` ({k[1]}): {dist[k]:,}")
    W("")
    W("**Why this matters.** Sampling ~1,000 pairs proportionally would reproduce this")
    W("skew. A model that answers with the majority technique unconditionally would score")
    W("well on technique accuracy while performing no analysis at all — and with a single")
    W("training run (SCOPE.md §6) there is no second attempt to correct for it.")
    W("")
    W("### Proposed mitigation: per-class cap")
    W("")
    if cap:
        cap_n, cap_total, cap_top = cap
        W(f"Cap each technique at **{cap_n} records** when sampling.")
        W("")
        W("| Property | Uncapped | Capped at " + str(cap_n) + " |")
        W("|---|---|---|")
        W(f"| Largest class share | {100.0 * top_share:.1f}% | {100.0 * cap_top:.1f}% |")
        W(f"| Pool available to sample | {lab:,} | {cap_total:,} |")
        W("")
        W(
            f"This keeps the pool at {cap_total:,} records — {cap_total / TARGET_PAIRS:.2f}× the "
            f"{TARGET_PAIRS:,} pairs needed, leaving slack for records later lost to the "
            f"token budget — while holding every class at or under "
            f"{100.0 * DOMINANCE_THRESHOLD:.0f}%."
        )
    else:
        W("No cap in the swept range both reaches the target size and holds every class")
        W(f"under {100.0 * DOMINANCE_THRESHOLD:.0f}%. The distribution is too skewed to")
        W("balance by capping alone.")
    W("")
    W("Three further rules for the dataset-build phase:")
    W("")
    W("1. **Floor rare classes.** Techniques with fewer than 20 records should either be")
    W("   included in full or dropped entirely — a class present with three examples")
    W("   teaches nothing and adds noise to per-class accuracy.")
    W("2. **Stratify the train/test split by technique**, so the 100-record test set is not")
    W("   accidentally all one class.")
    W("3. **Report the majority-class baseline** alongside technique accuracy. Without it,")
    W("   the metric cannot be distinguished from guessing the most common label.")
    W("")
    return "\n".join(L)


def main():
    lut_doc = yaml.safe_load(LOOKUP.read_text(encoding="utf-8"))
    exc_doc = yaml.safe_load(EXCLUDED.read_text(encoding="utf-8"))
    rows = lut_doc["techniques"]
    lut = {r["veris_path"]: r for r in rows}
    excluded_cats = {e["category"] for e in exc_doc["excluded_categories"]}

    attack_idx = load_attack_index()
    problems = validate_lookup(rows, attack_idx)

    records = load_records()
    n = len(records)

    stats = Counter()
    dist = Counter()
    uncovered_varieties = Counter()
    CYBER = ("hacking", "malware", "social")

    for rec in records:
        status, detail = label_record(rec, lut, excluded_cats)
        stats[status] += 1
        if status == "labelled":
            dist[(detail["attack_id"], detail["attack_name"])] += 1
        elif status == "uncovered":
            for v in detail:
                if v.split(".", 1)[0] in CYBER:
                    uncovered_varieties[v] += 1

    cyber_pool = sum(1 for r in records if set(r.get("action") or {}) & set(CYBER))
    nameable = sum(
        1
        for r in records
        if any(
            v.split(".", 1)[0] in CYBER and v.split(".", 1)[1] not in ("Unknown", "Other")
            for v in record_varieties(r)
        )
    )

    out = {
        "total": n,
        "labelled": stats["labelled"],
        "excluded": stats["excluded"],
        "uncovered": stats["uncovered"],
        "cyber_pool": cyber_pool,
        "nameable": nameable,
        "uncovered_top": uncovered_varieties.most_common(10),
        "attack_version": lut_doc.get("attack_version", "unknown"),
    }

    cap = propose_cap(dist, TARGET_PAIRS)
    md = build_markdown(out, dist, problems, cap, rows)
    print(md)
    OUT_MD.write_text(md, encoding="utf-8")
    print(f"\nwrote {OUT_MD}", file=sys.stderr)

    if problems:
        sys.exit(f"\nlookup validation failed with {len(problems)} problem(s)")


if __name__ == "__main__":
    main()
