#!/usr/bin/env python3
"""
Build the demo's scenario catalog from the test split.

Every field is derived from data already in the record -- nothing is invented:

  technique_id   test.jsonl `attack_id`
  technique_name labels/technique_lookup.yaml
  descriptor     src/chains.yaml, the skeleton's own `name`
  assets         the reference report's `## Affected Assets` section, which is
                 the reference's determination of which assets were actually
                 involved (the blob lists more than the incident touches)
  severity       the reference report's `## Severity` label

Shared by src/demo_api.py and importable for inspection.
"""

import json
import re

import yaml

from src import config as c

TEST = c.PROCESSED / "test.jsonl"
BLOBS = c.PROCESSED / "blobs.jsonl"
PREDS_TUNED = c.PROCESSED / "preds_tuned.jsonl"
CHAINS = c.ROOT / "src" / "chains.yaml"
LOOKUP = c.ROOT / "labels" / "technique_lookup.yaml"

ASSET_BULLET_RE = re.compile(r"^-\s+(?P<host>\S+)\s+\((?P<role>[a-z_]+)\)", re.M)
SEVERITY_RE = re.compile(r"^##\s+Severity\s*\n\s*(Low|Medium|High|Critical)\b", re.M | re.I)

# Plural-safe display names for the SCOPE.md 2.3 role enum.
ROLE_WORDS = {
    "user_workstation": ("workstation", "workstations"),
    "file_server": ("file server", "file servers"),
    "db_server": ("database server", "database servers"),
    "web_server": ("web server", "web servers"),
    "mail_server": ("mail server", "mail servers"),
    "domain_controller": ("domain controller", "domain controllers"),
    "backup_server": ("backup server", "backup servers"),
    "hypervisor": ("hypervisor", "hypervisors"),
    "network_device": ("network device", "network devices"),
}


def _phrase(roles):
    """'a workstation and a web server' from a role list, order preserved."""
    seen = []
    for r in roles:
        if r not in seen:
            seen.append(r)
    parts = []
    for r in seen:
        n = sum(1 for x in roles if x == r)
        singular, plural = ROLE_WORDS.get(r, (r.replace("_", " "), r.replace("_", " ") + "s"))
        parts.append(f"{n} {plural}" if n > 1 else f"a {singular}")
    if len(parts) == 1:
        return parts[0]
    if len(parts) == 2:
        return f"{parts[0]} and {parts[1]}"
    return ", ".join(parts[:-1]) + f", and {parts[-1]}"


def _load_jsonl(path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def build_catalog():
    """All 40 test scenarios, each with a grounded label and description."""
    chains = yaml.safe_load(CHAINS.read_text(encoding="utf-8"))
    descriptors = {s["id"]: s["name"] for s in chains["skeletons"]}
    # Optional plain-language copy for the demo catalog. A skeleton without it
    # falls back to the derived form below, so the catalog always renders.
    card_titles = {s["id"]: s["card_title"] for s in chains["skeletons"] if s.get("card_title")}
    card_blurbs = {s["id"]: s["card_blurb"] for s in chains["skeletons"] if s.get("card_blurb")}

    lookup = yaml.safe_load(LOOKUP.read_text(encoding="utf-8"))
    technique_names = {r["attack_id"]: r["attack_name"] for r in lookup["techniques"]}

    blobs = {r["incident_id"]: r for r in _load_jsonl(BLOBS)}
    preds = {r["incident_id"]: r for r in _load_jsonl(PREDS_TUNED)}

    out = []
    for row in _load_jsonl(TEST):
        iid = row["incident_id"]
        tid = row["attack_id"]
        blob = next(m["content"] for m in row["messages"] if m["role"] == "user")
        reference = next(m["content"] for m in row["messages"] if m["role"] == "assistant")

        skeleton = blobs[iid]["skeleton"]
        descriptor = descriptors.get(skeleton, skeleton)
        technique_name = technique_names.get(tid, tid)

        involved = ASSET_BULLET_RE.findall(reference)
        roles = [role for _, role in involved]
        hosts = [host for host, _ in involved]

        m = SEVERITY_RE.search(reference)
        severity = m.group(1).title() if m else "Unknown"

        # Label: technique name + skeleton descriptor + the primary asset role.
        primary = ROLE_WORDS.get(roles[0], (roles[0].replace("_", " "),))[0] if roles else None
        label = f"{technique_name} — {descriptor}"
        if primary:
            label += f" on {primary.title()}"

        if roles:
            description = (
                f"Involves {_phrase(roles)} ({', '.join(hosts[:3])})"
                f"{'...' if len(hosts) > 3 else ''}. Reference severity: {severity}."
            )
        else:
            description = f"Reference severity: {severity}."

        # Catalog copy. Prefers the skeleton's authored plain-language version;
        # otherwise derives a title and reuses the description above.
        card_title = card_titles.get(skeleton)
        if not card_title:
            card_title = descriptor.title()
            if primary:
                card_title += f" on {primary.title()}"
        card_blurb = card_blurbs.get(skeleton, description)

        out.append(
            {
                "id": iid,
                "technique_id": tid,
                "technique_name": technique_name,
                "descriptor": descriptor,
                "skeleton": skeleton,
                "label": label,
                "description": description,
                "card_title": card_title,
                "card_blurb": card_blurb,
                "has_plain_copy": skeleton in card_blurbs,
                "severity": severity,
                "asset_roles": roles,
                "asset_hosts": hosts,
                "blob": blob,
                "reference": reference,
                "prediction": preds[iid]["prediction"] if iid in preds else None,
                "blob_tokens": blobs[iid]["tokens"],
            }
        )

    out.sort(key=lambda s: (s["technique_id"], s["descriptor"]))
    return out


def grouped_catalog():
    """Catalog grouped by technique, for the UI's section headers."""
    groups = {}
    for s in build_catalog():
        groups.setdefault((s["technique_id"], s["technique_name"]), []).append(s)
    return [
        {"technique_id": tid, "technique_name": name, "scenarios": items}
        for (tid, name), items in sorted(groups.items())
    ]


if __name__ == "__main__":
    for group in grouped_catalog():
        print(
            f"\n{group['technique_id']}  {group['technique_name']}  "
            f"({len(group['scenarios'])} scenarios)"
        )
        for s in group["scenarios"]:
            print(f"  {s['label']}")
            print(f"    {s['description']}")
