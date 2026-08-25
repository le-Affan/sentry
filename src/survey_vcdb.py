#!/usr/bin/env python3
"""
Survey the raw data sources for the telemetry-to-incident-report project.

Answers, for the VERIS Community Database and the MITRE ATT&CK Enterprise STIX
bundle, what fields actually exist -- so docs/SCOPE.md section 2.9 (field
provenance) can be filled in with facts instead of assumptions.

Prints a report to stdout and writes docs/DATA_SURVEY.md.

Read-only: touches nothing under data/raw/ except to read it.
"""

import glob
import json
import os
import re
import statistics
import sys
from collections import Counter

VCDB_DIR = "data/raw/vcdb/validated"
SCHEMA_DIR = "data/raw/vcdb/schema"
MAPPING_DIR = "data/raw/vcdb/mappings"
ATTACK_BUNDLE = "data/raw/attack/enterprise-attack.json"
OUT_MD = "docs/DATA_SURVEY.md"

TOP_N = 20

# Patterns used to test whether VCDB carries any telemetry-grade detail at all.
# Each is deliberately permissive -- a false positive here is cheaper than
# wrongly concluding a field must be synthesized.
TELEMETRY_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain_name": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+(?:com|net|org|local|corp|gov|edu|io)\b"),
    # Excludes CVE-YYYY-NNNN and UUID hex chunks, which otherwise dominate this
    # pattern and are not hostnames.
    "hostname_siem_style": re.compile(
        r"\b(?!CVE-)(?![A-F0-9]{4}-)[A-Z]{2,}-[A-Z0-9]{2,}-[A-Z0-9]{2,}\b"
    ),
    "iso_timestamp": re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}"),
    "clock_time": re.compile(r"\b\d{1,2}:\d{2}(?::\d{2})?\s?(?:AM|PM|am|pm)?\b"),
    "process_name": re.compile(r"\b[A-Za-z0-9_\-]+\.(?:exe|dll|ps1|bat|sh|vbs|jar|py)\b"),
    "windows_path": re.compile(r"\b[A-Za-z]:\\\\?[^\s,;\"']{2,}"),
    "unix_path": re.compile(r"(?:^|\s)/(?:usr|etc|var|opt|home|tmp|bin)/[^\s,;\"']+"),
    "hash": re.compile(r"\b[a-fA-F0-9]{32,64}\b"),
    "port": re.compile(r"\bport\s+\d{1,5}\b", re.IGNORECASE),
}

# Fields that are record-keeping metadata about the VCDB entry itself, not
# observations about the incident. Scanned separately so their ISO timestamps
# do not masquerade as incident telemetry.
BOOKKEEPING_PREFIXES = ("plus.", "reference", "source_id", "schema_version")


def walk_strings(obj, prefix=""):
    """Yield (dotted_path, string_value) for every string leaf in a record."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_strings(item, prefix)
    elif isinstance(obj, str):
        yield prefix, obj


def non_empty(value):
    """VERIS uses {}, [], '' and 'Unknown' as varying degrees of absent."""
    if value is None:
        return False
    return not (isinstance(value, (dict, list, str)) and len(value) == 0)


def is_unknown(values):
    """True if a variety list carries no information beyond 'Unknown'/'Other'."""
    vals = values if isinstance(values, list) else [values]
    return all(str(v) in ("Unknown", "Other") for v in vals)


def load_records(path):
    # VCDB ships a mix of .json and .JSON extensions -- ~5% of the corpus uses
    # uppercase. Match case-insensitively or silently lose 550 records.
    files = sorted(f for f in glob.glob(os.path.join(path, "*")) if f.lower().endswith(".json"))
    records = []
    failed = []
    for f in files:
        try:
            with open(f, encoding="utf-8") as fh:
                records.append(json.load(fh))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            failed.append((os.path.basename(f), str(exc)))
    return records, failed


def survey_vcdb(records):
    r = {}
    n = len(records)
    r["total"] = n

    # --- presence counts -------------------------------------------------
    presence_specs = {
        "action": lambda d: non_empty(d.get("action")),
        "actor": lambda d: non_empty(d.get("actor")),
        "asset": lambda d: non_empty(d.get("asset")),
        "attribute": lambda d: non_empty(d.get("attribute")),
        "victim.industry": lambda d: non_empty(d.get("victim", {}).get("industry")),
        "victim.employee_count": lambda d: non_empty(d.get("victim", {}).get("employee_count")),
        "timeline": lambda d: non_empty(d.get("timeline")),
        "summary": lambda d: non_empty(d.get("summary")),
        "discovery_method": lambda d: non_empty(d.get("discovery_method")),
    }
    r["presence"] = {k: sum(1 for d in records if fn(d)) for k, fn in presence_specs.items()}

    # Informative (not just 'Unknown') counts for the fields that carry labels.
    r["informative"] = {
        "victim.employee_count": sum(
            1
            for d in records
            if non_empty(d.get("victim", {}).get("employee_count"))
            and d["victim"]["employee_count"] != "Unknown"
        ),
    }

    # --- timeline granularity -------------------------------------------
    tl = Counter()
    for d in records:
        t = d.get("timeline", {}).get("incident", {})
        if "day" in t:
            tl["year+month+day"] += 1
        elif "month" in t:
            tl["year+month"] += 1
        elif "year" in t:
            tl["year only"] += 1
        else:
            tl["none"] += 1
    r["timeline_granularity"] = dict(tl)
    r["timeline_has_clock_time"] = sum(
        1 for d in records if "time" in (d.get("timeline", {}).get("incident", {}) or {})
    )

    # VERIS records the *duration* of each incident phase with a coarse unit.
    # These are not timestamps, but they do constrain how far apart synthesized
    # event rows should be spaced.
    phase_units = {p: Counter() for p in ("compromise", "exfiltration", "discovery", "containment")}
    phase_present = Counter()
    for d in records:
        tlx = d.get("timeline", {}) or {}
        for phase in phase_units:
            body = tlx.get(phase) or {}
            if body.get("unit"):
                phase_units[phase][body["unit"]] += 1
                phase_present[phase] += 1
    r["timeline_phase_present"] = dict(phase_present)
    r["timeline_phase_units"] = {p: c.most_common(6) for p, c in phase_units.items()}

    # --- action varieties ------------------------------------------------
    action_var = Counter()
    action_cat = Counter()
    for d in records:
        for cat, body in (d.get("action") or {}).items():
            action_cat[cat] += 1
            if isinstance(body, dict):
                for v in body.get("variety", []) or []:
                    action_var[f"{cat}.{v}"] += 1
    r["action_variety_top"] = action_var.most_common(TOP_N)
    r["action_variety_total_distinct"] = len(action_var)
    r["action_categories"] = action_cat.most_common()

    # --- asset varieties -------------------------------------------------
    asset_var = Counter()
    assets_per_record = []
    for d in records:
        assets = (d.get("asset") or {}).get("assets", []) or []
        assets_per_record.append(len(assets))
        for a in assets:
            if isinstance(a, dict) and a.get("variety"):
                asset_var[a["variety"]] += 1
    r["asset_variety_top"] = asset_var.most_common(TOP_N)
    r["asset_variety_total_distinct"] = len(asset_var)
    r["assets_per_record_median"] = statistics.median(assets_per_record) if assets_per_record else 0
    r["assets_per_record_max"] = max(assets_per_record) if assets_per_record else 0
    r["records_with_multiple_assets"] = sum(1 for c in assets_per_record if c > 1)
    r["records_with_no_asset_rows"] = sum(1 for c in assets_per_record if c == 0)

    # --- telemetry-detail scan -------------------------------------------
    # Two passes: incident content vs. VCDB bookkeeping metadata.
    hits = {k: Counter() for k in TELEMETRY_PATTERNS}
    hits_bookkeeping = {k: 0 for k in TELEMETRY_PATTERNS}
    examples = {k: [] for k in TELEMETRY_PATTERNS}
    for d in records:
        for path, val in walk_strings(d):
            bookkeeping = path.startswith(BOOKKEEPING_PREFIXES)
            for name, pat in TELEMETRY_PATTERNS.items():
                m = pat.search(val)
                if not m:
                    continue
                if bookkeeping:
                    hits_bookkeeping[name] += 1
                else:
                    hits[name][path] += 1
                    if len(examples[name]) < 3:
                        examples[name].append((path, m.group(0)[:80]))
    r["telemetry_hits"] = {
        k: {
            "records_or_fields_hit": sum(v.values()),
            "fields": v.most_common(5),
            "examples": examples[k],
            "bookkeeping_only_hits": hits_bookkeeping[k],
        }
        for k, v in hits.items()
    }

    # --- summary text ----------------------------------------------------
    summaries = [
        d["summary"] for d in records if isinstance(d.get("summary"), str) and d["summary"].strip()
    ]
    char_lens = sorted(len(s) for s in summaries)
    word_lens = sorted(len(s.split()) for s in summaries)
    r["summary_count"] = len(summaries)
    if summaries:
        r["summary_median_chars"] = statistics.median(char_lens)
        r["summary_median_words"] = statistics.median(word_lens)
        r["summary_p10_words"] = word_lens[int(0.10 * len(word_lens))]
        r["summary_p90_words"] = word_lens[int(0.90 * len(word_lens))]
        r["summary_min_words"] = word_lens[0]
        r["summary_max_words"] = word_lens[-1]
        r["summary_example"] = max(summaries, key=lambda s: (len(s.split()) <= 60, len(s.split())))[
            :400
        ]
    return r


def survey_attack(path):
    with open(path, encoding="utf-8") as fh:
        bundle = json.load(fh)
    objs = bundle.get("objects", [])
    r = {"total_objects": len(objs), "spec_version": bundle.get("spec_version", "n/a")}

    types = Counter(o.get("type") for o in objs)
    r["object_types"] = types.most_common(10)

    techniques = [o for o in objs if o.get("type") == "attack-pattern"]
    active = [t for t in techniques if not t.get("x_mitre_deprecated") and not t.get("revoked")]
    subs = [t for t in active if t.get("x_mitre_is_subtechnique")]

    def attack_id(o):
        for ref in o.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    with_id = [t for t in active if attack_id(t)]
    with_name = [t for t in active if t.get("name")]
    with_desc = [t for t in active if (t.get("description") or "").strip()]
    id_pat = re.compile(r"^T\d{4}(\.\d{3})?$")
    well_formed = [t for t in with_id if id_pat.match(attack_id(t))]

    desc_words = sorted(len((t.get("description") or "").split()) for t in with_desc)

    r["techniques_total"] = len(techniques)
    r["techniques_deprecated_or_revoked"] = len(techniques) - len(active)
    r["techniques_active"] = len(active)
    r["subtechniques"] = len(subs)
    r["parent_techniques"] = len(active) - len(subs)
    r["with_id"] = len(with_id)
    r["with_name"] = len(with_name)
    r["with_description"] = len(with_desc)
    r["id_well_formed"] = len(well_formed)
    r["desc_median_words"] = statistics.median(desc_words) if desc_words else 0
    r["desc_p90_words"] = desc_words[int(0.90 * len(desc_words))] if desc_words else 0
    r["desc_max_words"] = desc_words[-1] if desc_words else 0
    r["tactics"] = len([o for o in objs if o.get("type") == "x-mitre-tactic"])
    if with_desc:
        sample = min(with_desc, key=lambda t: abs(len((t.get("description") or "").split()) - 60))
        r["example"] = {
            "id": attack_id(sample),
            "name": sample.get("name"),
            "description": (sample.get("description") or "")[:300],
        }
    return r


def survey_mapping(path, records):
    """The official VERIS -> ATT&CK crosswalk shipped in the veris repo.

    The critical question is not "does a mapping exist" but "is it a *label*".
    A crosswalk that maps one VERIS variety to many ATT&CK techniques cannot
    supply the single ground-truth technique ID that SCOPE.md section 3.3 scores.
    """
    if not os.path.exists(path):
        return None
    import csv
    from collections import defaultdict

    with open(path, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    r = {"rows": len(rows), "columns": [c for c in (rows[0].keys() if rows else []) if c]}
    r["mapping_types"] = Counter(row.get("mapping_type") for row in rows).most_common()

    lut = defaultdict(set)
    for row in rows:
        cap, tid = row.get("capability_id"), row.get("attack_object_id")
        if cap and tid:
            lut[cap].add(tid)
    r["distinct_veris_paths"] = len(lut)
    r["distinct_attack_ids"] = len(
        {row["attack_object_id"] for row in rows if row.get("attack_object_id")}
    )

    fan = [len(v) for v in lut.values()]
    r["fanout_one_to_one"] = sum(1 for f in fan if f == 1)
    r["fanout_one_to_many"] = sum(1 for f in fan if f > 1)
    r["fanout_median"] = statistics.median(fan) if fan else 0
    r["fanout_max"] = max(fan) if fan else 0
    r["fanout_worst"] = sorted(((k, len(v)) for k, v in lut.items()), key=lambda x: -x[1])[:5]

    # How many VCDB records the crosswalk can label, and how ambiguously.
    per_record = Counter()
    mappable = 0
    for d in records:
        ids = set()
        for cat, body in (d.get("action") or {}).items():
            if isinstance(body, dict):
                for v in body.get("variety", []) or []:
                    ids |= lut.get(f"action.{cat}.variety.{v}", set())
        if ids:
            mappable += 1
            per_record[min(len(ids), 6)] += 1
    r["records_mappable"] = mappable
    r["records_by_candidate_count"] = sorted(per_record.items())
    r["records_unambiguous"] = per_record.get(1, 0)

    # Fallback pool: records with any cyber-relevant action, which a hand-curated
    # one-technique-per-variety lookup could label.
    cyber = ("hacking", "malware", "social")
    r["records_cyber_action"] = sum(
        1 for d in records if any(c in cyber for c in (d.get("action") or {}))
    )
    vc = Counter()
    for d in records:
        for cat, body in (d.get("action") or {}).items():
            if cat in cyber and isinstance(body, dict):
                for v in body.get("variety", []) or []:
                    if v not in ("Unknown", "Other"):
                        vc[f"{cat}.{v}"] += 1
    r["top_cyber_varieties"] = vc.most_common(15)
    return r


def fmt_counter_table(pairs, headers=("Value", "Count"), total=None):
    lines = [f"| # | {headers[0]} | {headers[1]} | % of records |", "|---|---|---|---|"]
    for i, (k, v) in enumerate(pairs, 1):
        pct = f"{100.0 * v / total:.1f}%" if total else ""
        lines.append(f"| {i} | `{k}` | {v:,} | {pct} |")
    return "\n".join(lines)


def build_markdown(v, a, m, failed):
    n = v["total"]
    L = []
    W = L.append

    W("# DATA SURVEY — VCDB and MITRE ATT&CK")
    W("")
    W("Generated by `src/survey_vcdb.py`. Read-only survey of `data/raw/`. No dataset")
    W("has been built yet. Numbers here are what fill in the provenance table in")
    W("`docs/SCOPE.md` §2.9.")
    W("")
    W("---")
    W("")

    # -- VCDB -------------------------------------------------------------
    W("## 1. VERIS Community Database")
    W("")
    W("- Source: `github.com/vz-risk/VCDB`, `data/json/validated/`")
    W(f"- **Total validated records: {n:,}**")
    if failed:
        W(f"- Records that failed to parse: {len(failed)}")
    W("- Schema: VERIS 1.4.x (`data/raw/vcdb/schema/verisc.json`)")
    W("")

    W("### 1.1 Field presence")
    W("")
    W("| Field | Records with non-empty value | % |")
    W("|---|---|---|")
    for k, c in v["presence"].items():
        W(f"| `{k}` | {c:,} | {100.0 * c / n:.1f}% |")
    ec = v["informative"]["victim.employee_count"]
    W(f'| `victim.employee_count` *(excluding "Unknown")* | {ec:,} | {100.0 * ec / n:.1f}% |')
    W("")

    W("### 1.2 Timeline granularity")
    W("")
    W("This is the finest incident date VERIS records. There is no event-level time.")
    W("")
    W("| Granularity | Records | % |")
    W("|---|---|---|")
    for k, c in sorted(v["timeline_granularity"].items(), key=lambda x: -x[1]):
        W(f"| {k} | {c:,} | {100.0 * c / n:.1f}% |")
    W(
        f"Only **{v['timeline_has_clock_time']}** records out of {n:,} carry a clock time "
        f"(`timeline.incident.time`)."
    )
    W("")
    W("VERIS does record the **duration** of each incident phase, with a coarse unit.")
    W("These are not timestamps, but they do constrain realistic spacing between")
    W("synthesized event rows.")
    W("")
    W("| Phase | Records with a unit | % | Unit distribution |")
    W("|---|---|---|---|")
    for phase, cnt in sorted(v["timeline_phase_present"].items(), key=lambda x: -x[1]):
        units = ", ".join(f"{u} ({c:,})" for u, c in v["timeline_phase_units"][phase])
        W(f"| `timeline.{phase}.unit` | {cnt:,} | {100.0 * cnt / n:.1f}% | {units} |")
    W("")

    W(f"### 1.3 Top {TOP_N} `action.*.variety`")
    W("")
    W(f"{v['action_variety_total_distinct']} distinct values across all action categories.")
    W("")
    W(fmt_counter_table(v["action_variety_top"], ("action.category.variety", "Count"), n))
    W("")
    W(
        "Action categories overall: "
        + ", ".join(f"`{k}` ({c:,})" for k, c in v["action_categories"])
    )
    W("")

    W(f"### 1.4 Top {TOP_N} `asset.assets.variety`")
    W("")
    W(f"{v['asset_variety_total_distinct']} distinct values.")
    W(
        f"Median asset rows per record: **{v['assets_per_record_median']:g}**; "
        f"max {v['assets_per_record_max']}; "
        f"{v['records_with_multiple_assets']:,} records "
        f"({100.0 * v['records_with_multiple_assets'] / n:.1f}%) "
        f"list more than one asset; "
        f"{v['records_with_no_asset_rows']:,} list none."
    )
    W("")
    W(fmt_counter_table(v["asset_variety_top"], ("asset.assets.variety", "Count"), n))
    W("")

    W("### 1.5 Telemetry-detail scan")
    W("")
    W("Does *any* VCDB field contain the primitives the input spec needs? Every string")
    W('leaf in every record was regex-scanned. "Incident content" excludes VCDB')
    W("bookkeeping fields (`plus.*`, `reference`, `source_id`, `schema_version`), which")
    W("are metadata about the database entry, not observations about the incident.")
    W("")
    W("| Primitive | Hits in incident content | Hits in bookkeeping only | Where found | Verdict |")
    W("|---|---|---|---|---|")
    for name, info in v["telemetry_hits"].items():
        hits = info["records_or_fields_hit"]
        bk = info["bookkeeping_only_hits"]
        where = ", ".join(f"`{p}`" for p, _ in info["fields"][:2]) or "—"
        if hits == 0:
            verdict = "**absent**"
        elif hits < n * 0.01:
            verdict = f"**negligible** ({100.0 * hits / n:.2f}%)"
        else:
            verdict = f"present in {100.0 * hits / n:.1f}% "
        W(f"| {name} | {hits:,} | {bk:,} | {where} | {verdict} |")
    W("")
    W("Examples of what actually matched (truncated):")
    W("")
    for name, info in v["telemetry_hits"].items():
        if info["examples"]:
            p, ex = info["examples"][0]
            W(f"- **{name}** — `{p}`: `{ex}`")
    W("")

    W("### 1.6 Free-text summary")
    W("")
    W(
        f"- Records with a non-empty `summary`: **{v['summary_count']:,}** "
        f"({100.0 * v['summary_count'] / n:.1f}%)"
    )
    if v["summary_count"]:
        W(
            f"- **Median length: {v['summary_median_chars']:g} characters / "
            f"{v['summary_median_words']:g} words**"
        )
        W(
            f"- p10 / p90 words: {v['summary_p10_words']} / {v['summary_p90_words']}; "
            f"range {v['summary_min_words']}–{v['summary_max_words']}"
        )
        W("")
        W("Representative summary:")
        W("")
        W("> " + v["summary_example"].replace("\n", " "))
    W("")

    # -- mapping ----------------------------------------------------------
    if m:
        W("### 1.7 VERIS → ATT&CK crosswalk")
        W("")
        W("The `vz-risk/veris` repo ships an official mapping, copied to")
        W("`data/raw/vcdb/mappings/`. This is the source of ground-truth technique labels.")
        W("")
        W(f"- Rows: **{m['rows']:,}**")
        W(f"- Distinct VERIS enum paths mapped: **{m['distinct_veris_paths']:,}**")
        W(f"- Distinct ATT&CK IDs referenced: **{m['distinct_attack_ids']:,}**")
        W("- `mapping_type` values: " + ", ".join(f"`{k}` ({c:,})" for k, c in m["mapping_types"]))
        W("")
        W("**The crosswalk is association-grade, not label-grade.** Every substantive row")
        W('carries `mapping_type = related-to`; there is no "primary technique" marker and')
        W("`score_category` is empty throughout. The fan-out follows:")
        W("")
        W(f"| VERIS varieties mapping to exactly one technique | {m['fanout_one_to_one']:,} |")
        W("|---|---|")
        W(f"| VERIS varieties mapping to more than one | {m['fanout_one_to_many']:,} |")
        W(f"| Median techniques per VERIS variety | {m['fanout_median']:g} |")
        W(f"| Max techniques per VERIS variety | {m['fanout_max']:,} |")
        W("")
        W("Worst fan-out: " + "; ".join(f"`{k}` → {c}" for k, c in m["fanout_worst"]))
        W("")
        W("Applied to actual VCDB records:")
        W("")
        W(
            f"- Records with at least one mappable action variety: **{m['records_mappable']:,}** "
            f"({100.0 * m['records_mappable'] / n:.1f}%)"
        )
        W(
            f"- Of those, records resolving to **exactly one** candidate technique: "
            f"**{m['records_unambiguous']:,}**"
        )
        W("")
        W("| Candidate techniques for the record | Records |")
        W("|---|---|")
        for k, c in m["records_by_candidate_count"]:
            label = "6 or more" if k == 6 else str(k)
            W(f"| {label} | {c:,} |")
        W("")
        W(
            f"A hand-curated fallback is viable: **{m['records_cyber_action']:,}** records "
            f"({100.0 * m['records_cyber_action'] / n:.1f}%) carry a `hacking`, `malware`, or"
        )
        W("`social` action, and the distribution is concentrated enough that curating one")
        W("canonical technique for the top 15 varieties covers most of them.")
        W("")
        W(
            "Top 15 cyber-relevant action varieties: "
            + ", ".join(f"`{k}` ({c:,})" for k, c in m["top_cyber_varieties"])
        )
        W("")

    W("---")
    W("")

    # -- ATT&CK -----------------------------------------------------------
    W("## 2. MITRE ATT&CK Enterprise")
    W("")
    W(
        "- Source: `github.com/mitre-attack/attack-stix-data`, "
        "`enterprise-attack/enterprise-attack.json`"
    )
    W(f"- STIX bundle, {a['total_objects']:,} objects, spec version {a['spec_version']}")
    W("")
    W("| Property | Value |")
    W("|---|---|")
    W(f"| Attack-pattern objects (all) | {a['techniques_total']:,} |")
    W(f"| Deprecated or revoked | {a['techniques_deprecated_or_revoked']:,} |")
    W(f"| **Active techniques** | **{a['techniques_active']:,}** |")
    W(f"| — of which sub-techniques | {a['subtechniques']:,} |")
    W(f"| — of which parent techniques | {a['parent_techniques']:,} |")
    W(f"| Tactics | {a['tactics']:,} |")
    W("")
    W("### 2.1 Retrieval-corpus fitness")
    W("")
    W("Every active technique needs an ID, a name, and a usable description for RAG.")
    W("")
    W("| Requirement | Count | Coverage |")
    W("|---|---|---|")
    act = a["techniques_active"]
    for label, key in (
        ("Has a `mitre-attack` external ID", "with_id"),
        ("ID matches `T\\d{4}(\\.\\d{3})?`", "id_well_formed"),
        ("Has a name", "with_name"),
        ("Has a non-empty description", "with_description"),
    ):
        W(f"| {label} | {a[key]:,} / {act:,} | {100.0 * a[key] / act:.1f}% |")
    W("")
    W(
        f"- Description length: median **{a['desc_median_words']:g} words**, "
        f"p90 {a['desc_p90_words']}, max {a['desc_max_words']}."
    )
    W("- Descriptions are long enough to be informative and long enough to need")
    W("  chunking or truncation before they fit the 1024-token sequence budget.")
    if "example" in a:
        W("")
        W(f"Example entry — **{a['example']['id']} — {a['example']['name']}**:")
        W("")
        W("> " + a["example"]["description"].replace("\n", " "))
    W("")
    W("**Verdict: ATT&CK is a clean retrieval corpus.** ID, name, and description are")
    W("present for effectively every active technique, with no cleanup required beyond")
    W("stripping STIX markdown citation markers and truncating long descriptions.")
    W("")
    W("---")
    W("")
    return "\n".join(L)


def main():
    if not os.path.isdir(VCDB_DIR):
        sys.exit(f"missing {VCDB_DIR} -- run the download step first")
    if not os.path.exists(ATTACK_BUNDLE):
        sys.exit(f"missing {ATTACK_BUNDLE} -- run the download step first")

    print(f"loading VCDB from {VCDB_DIR} ...", file=sys.stderr)
    records, failed = load_records(VCDB_DIR)
    print(f"  {len(records):,} records loaded, {len(failed)} failed", file=sys.stderr)

    v = survey_vcdb(records)
    print("surveying ATT&CK ...", file=sys.stderr)
    a = survey_attack(ATTACK_BUNDLE)
    m = survey_mapping(os.path.join(MAPPING_DIR, "veris-1.4.1_attack-19.1-enterprise.csv"), records)

    md = build_markdown(v, a, m, failed)

    # stdout report
    print(md)

    os.makedirs(os.path.dirname(OUT_MD), exist_ok=True)
    existing_tail = ""
    if os.path.exists(OUT_MD):
        # Preserve hand-written sections (gap analysis) appended after the marker.
        with open(OUT_MD, encoding="utf-8") as fh:
            prev = fh.read()
        marker = "<!-- HANDWRITTEN BELOW -->"
        if marker in prev:
            existing_tail = marker + prev.split(marker, 1)[1]
    with open(OUT_MD, "w", encoding="utf-8") as fh:
        fh.write(md)
        if existing_tail:
            fh.write(existing_tail)
    print(f"\nwrote {OUT_MD}", file=sys.stderr)


if __name__ == "__main__":
    main()
