#!/usr/bin/env python3
"""
Score base and tuned predictions against the reference reports.

Implements the metric set in SCOPE.md section 5, keeping its two-tier split:
primary claims are report quality, format adherence, and grounding; technique
and severity accuracy are secondary compliance signals and are ALWAYS reported
against their majority-class baseline, because the corpus is skewed enough
(66.0% High, 17.5% T1190) that raw accuracy alone is not interpretable.

Pure local text processing -- no GPU, no Kaggle. BERTScore uses a small model
(distilbert) rather than the roberta-large default, so this runs on CPU in
minutes.

    python -m src.evaluate
"""

import json
import re
import statistics
import sys
from collections import Counter

from src import config as c
from src.generate_reports import ENTITY_RE, SECTION_RE

TEST = c.PROCESSED / "test.jsonl"
PREDS = {"base": c.PROCESSED / "preds_base.jsonl", "tuned": c.PROCESSED / "preds_tuned.jsonl"}
OUT_MD = c.DOCS / "EVAL_RESULTS.md"
OUT_JSON = c.PROCESSED / "eval_results.json"

# Small and CPU-friendly. bert-score's default is roberta-large, which is
# ~1.4GB and pointless for a 40-example comparison.
BERT_MODEL = "distilbert-base-uncased"
BERT_LAYER = 5

# Majority-class baselines, measured on the 400-pair corpus in DATASET_STATS.md.
SEVERITY_BASELINE = 0.660
SEVERITY_BASELINE_LABEL = "High"
TECHNIQUE_BASELINE = 0.175
TECHNIQUE_BASELINE_LABEL = "T1190"

REQUIRED_HEADINGS = list(c.SECTIONS)
HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.M)
# SCOPE.md 3 says "No other headings." A model that emits the six required `##`
# headings but also sprinkles `###` sub-headings inside them is not compliant --
# checking only the `##` level scores that as a pass, which it is not.
ANY_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$", re.M)
TECH_ID_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")
SEVERITY_RE = re.compile(r"^\s*(Low|Medium|High|Critical)\b", re.I)


def load_jsonl(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def headings_of(text):
    return [h.strip() for h in HEADING_RE.findall(text)]


def format_ok(text):
    """Exactly the six required headings, in order, and no other heading."""
    if headings_of(text) != REQUIRED_HEADINGS:
        return False
    # Any heading at a level other than `##` is an extra section.
    return all(hashes == "##" for hashes, _ in ANY_HEADING_RE.findall(text))


def heading_violations(text):
    """Why a report failed the format check -- for the write-up."""
    out = []
    got = headings_of(text)
    if got != REQUIRED_HEADINGS:
        missing = [h for h in REQUIRED_HEADINGS if h not in got]
        extra = [h for h in got if h not in REQUIRED_HEADINGS]
        if missing:
            out.append(f"missing: {missing}")
        if extra:
            out.append(f"unexpected: {extra}")
        if not missing and not extra:
            out.append("wrong order")
    other = sorted({h for lvl, h in ANY_HEADING_RE.findall(text) if lvl != "##"})
    if other:
        out.append(f"non-## headings: {other[:4]}")
    return out


def section(text, key):
    m = SECTION_RE[key].search(text)
    return m.group(1).strip() if m else ""


def technique_of(text):
    """First ATT&CK ID in the Attack Technique section only."""
    m = TECH_ID_RE.search(section(text, "technique"))
    if not m:
        return None
    return f"T{m.group(1)}" + (f".{m.group(2)}" if m.group(2) else "")


def severity_of(text):
    body = section(text, "severity")
    first = body.splitlines()[0] if body else ""
    m = SEVERITY_RE.match(first)
    return m.group(1).title() if m else None


def grounding(pred, blob):
    """(n_ungrounded, n_total) entities in the prediction vs its own blob."""
    total = ungrounded = 0
    bad = []
    for kind, pat in ENTITY_RE.items():
        in_blob = set(pat.findall(blob))
        for ent in set(pat.findall(pred)):
            total += 1
            if ent not in in_blob:
                ungrounded += 1
                bad.append(f"{kind}:{ent}")
    return ungrounded, total, bad


def evaluate(variant, rows, blobs, refs, gold, tokenizer):
    from rouge_score import rouge_scorer

    scorer = rouge_scorer.RougeScorer(["rougeL"], use_stemmer=True)

    preds = [r["prediction"] for r in rows]
    ids = [r["incident_id"] for r in rows]
    references = [refs[i] for i in ids]

    rouge = [
        scorer.score(ref, pred)["rougeL"].fmeasure
        for ref, pred in zip(references, preds, strict=True)
    ]

    from bert_score import score as bert_score

    _, _, f1 = bert_score(
        preds, references, model_type=BERT_MODEL, num_layers=BERT_LAYER, verbose=False, batch_size=8
    )
    bert_f1 = [float(x) for x in f1]

    fmt = [format_ok(p) for p in preds]
    fmt_problems = Counter()
    for p in preds:
        for v in heading_violations(p):
            fmt_problems[v.split(":")[0]] += 1

    sev_pred = [severity_of(p) for p in preds]
    sev_gold = [severity_of(refs[i]) for i in ids]
    sev_ok = [p is not None and p == g for p, g in zip(sev_pred, sev_gold, strict=True)]

    tech_pred = [technique_of(p) for p in preds]
    tech_gold = [gold[i] for i in ids]
    tech_ok = [p is not None and p == g for p, g in zip(tech_pred, tech_gold, strict=True)]

    ground = [grounding(p, blobs[i]) for p, i in zip(preds, ids, strict=True)]
    n_with_bad = sum(1 for u, _, _ in ground if u)
    tot_ent = sum(t for _, t, _ in ground)
    tot_bad = sum(u for u, _, _ in ground)
    offenders = [(i, b) for (u, _, b), i in zip(ground, ids, strict=True) if u]

    lengths = sorted(len(tokenizer.encode(p)) for p in preds)

    return {
        "variant": variant,
        "n": len(rows),
        "rougeL_mean": statistics.mean(rouge),
        "bertscore_mean": statistics.mean(bert_f1),
        "format_rate": sum(fmt) / len(fmt),
        "format_problems": fmt_problems.most_common(5),
        "severity_acc": sum(sev_ok) / len(sev_ok),
        "technique_acc": sum(tech_ok) / len(tech_ok),
        "technique_parsed": sum(1 for t in tech_pred if t) / len(tech_pred),
        "severity_parsed": sum(1 for s in sev_pred if s) / len(sev_pred),
        "grounded_clean_rate": 1 - n_with_bad / len(rows),
        "ungrounded_entity_rate": (tot_bad / tot_ent) if tot_ent else 0.0,
        "n_reports_with_ungrounded": n_with_bad,
        "total_entities": tot_ent,
        "len_median": statistics.median(lengths),
        "len_p90": lengths[int(0.9 * len(lengths))],
        "offenders": offenders[:10],
        "tech_confusion": Counter(
            f"{g}->{p}" for p, g, ok in zip(tech_pred, tech_gold, tech_ok, strict=True) if not ok
        ).most_common(5),
        "sev_confusion": Counter(
            f"{g}->{p}" for p, g, ok in zip(sev_pred, sev_gold, sev_ok, strict=True) if not ok
        ).most_common(5),
    }


def pct(x):
    return f"{100 * x:.1f}%"


def main():
    from transformers import AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(c.BASE_MODEL)

    test = load_jsonl(TEST)
    blobs, refs, gold = {}, {}, {}
    for row in test:
        iid = row["incident_id"]
        blobs[iid] = next(m["content"] for m in row["messages"] if m["role"] == "user")
        refs[iid] = next(m["content"] for m in row["messages"] if m["role"] == "assistant")
        gold[iid] = row["attack_id"]

    results = {}
    for variant, path in PREDS.items():
        if not path.exists():
            sys.exit(f"missing {path}")
        print(f"scoring {variant} ...", file=sys.stderr)
        results[variant] = evaluate(variant, load_jsonl(path), blobs, refs, gold, tokenizer)

    b, t = results["base"], results["tuned"]

    def row(label, key, fmt=pct, extra=""):
        return f"| {label} | {fmt(b[key])} | {fmt(t[key])} | {extra} |"

    L = []
    W = L.append
    W("# EVALUATION RESULTS")
    W("")
    W("`Qwen2.5-3B-Instruct` base vs the same model with the QLoRA adapter, on the")
    W(f"held-out test split ({b['n']} examples). Greedy decoding, fixed seed, identical")
    W("system prompt — the two columns differ only by the adapter.")
    W("")
    W("Generated by `src/evaluate.py`. Metrics follow the two-tier split in SCOPE.md §5.")
    W("")
    W("---")
    W("")
    W("## Results")
    W("")
    W("| Metric | Base | Tuned | Baseline / note |")
    W("|---|---|---|---|")
    W("| **Primary — report quality** | | | |")
    W(row("ROUGE-L (mean F1)", "rougeL_mean", lambda x: f"{x:.4f}"))
    W(row("BERTScore (mean F1)", "bertscore_mean", lambda x: f"{x:.4f}", f"`{BERT_MODEL}`"))
    W("| **Primary — format adherence** | | | |")
    W(row("Six headings, correct order", "format_rate", pct, "exact match, no extras"))
    W("| **Primary — grounding** | | | |")
    W(row("Reports with no invented entity", "grounded_clean_rate", pct, "higher is better"))
    W(row("Ungrounded entity rate", "ungrounded_entity_rate", pct, "lower is better"))
    W("| **Secondary — compliance** | | | |")
    W(
        row(
            "Technique-ID accuracy",
            "technique_acc",
            pct,
            f"**baseline {pct(TECHNIQUE_BASELINE)}** ({TECHNIQUE_BASELINE_LABEL})",
        )
    )
    W(
        row(
            "Severity accuracy",
            "severity_acc",
            pct,
            f"**baseline {pct(SEVERITY_BASELINE)}** ({SEVERITY_BASELINE_LABEL})",
        )
    )
    W("| **Supporting counters** | | | |")
    W(row("Attack Technique section parseable", "technique_parsed", pct))
    W(row("Severity section parseable", "severity_parsed", pct))
    W(f"| Output length, median tokens | {b['len_median']:.0f} | {t['len_median']:.0f} | |")
    W(f"| Output length, p90 tokens | {b['len_p90']} | {t['len_p90']} | |")
    W("")
    W("### Lift over baseline")
    W("")
    W("| Secondary metric | Base vs baseline | Tuned vs baseline |")
    W("|---|---|---|")
    W(
        f"| Technique-ID | {100 * (b['technique_acc'] - TECHNIQUE_BASELINE):+.1f} pts "
        f"| {100 * (t['technique_acc'] - TECHNIQUE_BASELINE):+.1f} pts |"
    )
    W(
        f"| Severity | {100 * (b['severity_acc'] - SEVERITY_BASELINE):+.1f} pts "
        f"| {100 * (t['severity_acc'] - SEVERITY_BASELINE):+.1f} pts |"
    )
    W("")

    for name, r in (("Base", b), ("Tuned", t)):
        if r["tech_confusion"] or r["sev_confusion"]:
            W(
                f"**{name} — most common errors.** "
                f"Technique: {r['tech_confusion'] or 'none'}. "
                f"Severity: {r['sev_confusion'] or 'none'}."
            )
            W("")

    OUT_JSON.write_text(json.dumps(results, indent=2, default=str))
    OUT_MD.write_text("\n".join(L), encoding="utf-8")
    print("\n".join(L))
    print(f"\nwrote {OUT_MD} and {OUT_JSON}", file=sys.stderr)


if __name__ == "__main__":
    main()
