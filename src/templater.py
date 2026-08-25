#!/usr/bin/env python3
"""
Render a VCDB record into a synthetic telemetry blob per SCOPE.md section 2.

Implements docs/TEMPLATING_DESIGN.md:
  * a skeleton is chosen per record, seeded from incident_id (reproducible)
  * events are emitted in a random *valid* topological sort of the skeleton's
    dependency graph, not a fixed order
  * 1-3 benign noise events are injected at valid positions
  * the blob is measured with the real Qwen2.5 tokenizer and truncated by the
    section 2.7 ladder until it fits MAX_INPUT_TOKENS

Everything except the VCDB-derived fields is synthesized. docs/SCOPE.md section
2.9 records which is which; DATA_SURVEY.md section 3.2 explains why there is no
alternative.

No reference reports are produced here -- that is a later phase.
"""

import hashlib
import json
import random
import sys
from collections import Counter
from datetime import datetime, timedelta

import yaml

from src import config as c

CHAINS = c.ROOT / "src" / "chains.yaml"

MAX_EVENTS = c.MAX_EVENT_ROWS

# --- synthetic entity vocabularies -----------------------------------------
# Documentation-reserved ranges only (RFC 5737 / RFC 2606), so no blob can ever
# name a real host or address.
SITES = ["HQ", "BR1", "BR2", "DC1", "EU1", "APAC"]
EXT_NETS = ["203.0.113", "198.51.100", "192.0.2"]
INT_NETS = ["10.14", "10.22", "172.16", "192.168"]
EXT_DOMAINS = [
    "invoices-billing.example",
    "secure-docs.example.net",
    "vendor-portal.example.org",
    "account-verify.example",
    "shared-files.example.net",
]
FIRST = [
    "j.reyes",
    "m.okafor",
    "s.lindqvist",
    "a.duarte",
    "k.tanaka",
    "r.mbeki",
    "l.novak",
    "d.ferreira",
    "n.haddad",
    "p.singh",
]
SVC = ["svc_backup", "svc_sql", "svc_iis", "svc_monitor", "svc_deploy", "svc_scan"]
PAYLOAD_FILES = [
    "Invoice_Q1_overdue.xlsm",
    "Remittance_Advice.docm",
    "Statement_0417.pdf.exe",
    "shipping_notice.zip",
    "payroll_update.xlsm",
    "contract_final.docm",
]
DROP_PATHS = [
    r"C:\Users\Public\svcupd.exe",
    r"C:\ProgramData\winsys\hostsvc.exe",
    r"C:\Windows\Temp\msupd.dll",
    r"C:\Users\Public\Libraries\dsvc.exe",
    r"C:\ProgramData\Intel\drv64.exe",
]
OS_USER = ["Windows 10 22H2", "Windows 11 23H2", "macOS 14.4"]
OS_SRV = ["Windows Server 2019", "Windows Server 2022", "Ubuntu 22.04 LTS", "RHEL 9"]

# VERIS asset variety prefix -> our role enum (SCOPE.md 2.3).
ROLE_BY_ASSET = {
    "S - Web application": "web_server",
    "S - Database": "db_server",
    "S - File": "file_server",
    "S - Mail": "mail_server",
    "S - Directory": "domain_controller",
    "S - Remote access": "network_device",
    "S - Backup": "backup_server",
    "U - Desktop or laptop": "user_workstation",
    "U - Desktop": "user_workstation",
    "U - Laptop": "user_workstation",
    "N - Router or switch": "network_device",
    "N - Firewall": "network_device",
    "S - Virtual Host": "hypervisor",
}
# Kept deliberately short. Hostnames appear twice per event row, and the Qwen
# tokenizer charges 12 tokens for "HQ-SRV-FS01-4821" against 5 for "HQ-FS01" --
# roughly 100 tokens per blob, which is the difference between fitting the
# budget and not.
ROLE_PREFIX = {
    "user_workstation": "WKS",
    "file_server": "FS",
    "db_server": "DB",
    "web_server": "WEB",
    "mail_server": "MX",
    "domain_controller": "DC",
    "backup_server": "BK",
    "hypervisor": "VH",
    "network_device": "SW",
}

# VERIS confidentiality data variety -> SCOPE.md data_sensitivity enum.
SENSITIVITY = {
    "Medical": "PHI",
    "Payment": "PCI",
    "Personal": "PII",
    "Credentials": "Secrets",
    "Internal": "Internal",
    "Secrets": "Secrets",
    "Bank": "PCI",
    "Copyrighted": "Internal",
    "Classified": "Secrets",
    "Digital certificate": "Secrets",
    "System": "Internal",
}

EMP_BANDS = {
    "1 to 10": (1, 10),
    "11 to 100": (11, 100),
    "101 to 1000": (101, 1000),
    "1001 to 10000": (1001, 10000),
    "10001 to 25000": (10001, 25000),
    "25001 to 50000": (25001, 50000),
    "50001 to 100000": (50001, 100000),
    "Over 100000": (100001, 250000),
    "Small": (1, 1000),
    "Large": (1001, 100000),
}

TOOLS = ["Splunk ES", "Microsoft Sentinel", "Elastic Security", "QRadar", "Chronicle"]


# ---------------------------------------------------------------------------
# Truncation ladder -- SCOPE.md 2.7, in fire order
# ---------------------------------------------------------------------------
LADDER = [
    "1_trim_descriptions",
    "2_drop_events",
    "3_drop_detections",
    "4_drop_assets",
    "5_drop_analyst_notes",
]


def seeded_rng(incident_id):
    """Deterministic per-record RNG, so a rebuild reproduces the same corpus."""
    h = hashlib.sha256(str(incident_id).encode()).hexdigest()
    return random.Random(int(h[:16], 16))


class Entities:
    """Synthesized names for one incident. All fabricated -- see SCOPE.md 2.9."""

    def __init__(self, rng, roles):
        site = rng.choice(SITES)
        self.site = site
        self.assets = []
        seen = set()
        for i, role in enumerate(roles, 1):
            prefix = ROLE_PREFIX.get(role, "SRV")
            host = f"{site}-{prefix}{rng.randint(1, 99):02d}"
            while host in seen:
                host = f"{site}-{prefix}{rng.randint(1, 99):02d}"
            seen.add(host)
            net = rng.choice(INT_NETS)
            # INT_NETS entries are /16 prefixes, so exactly two octets complete them.
            ip = net + "".join(f".{rng.randint(1, 254)}" for _ in range(2))
            self.assets.append(
                {
                    "asset_id": f"A-{i:03d}",
                    "hostname": host,
                    "role": role,
                    "os": rng.choice(OS_USER if role == "user_workstation" else OS_SRV),
                    "ip": ip,
                }
            )
        self.user = "CORP\\" + rng.choice(FIRST)
        self.svc = "CORP\\" + rng.choice(SVC)
        self.ext_ip = f"{rng.choice(EXT_NETS)}.{rng.randint(2, 254)}"
        self.domain = rng.choice(EXT_DOMAINS)
        self.file = rng.choice(PAYLOAD_FILES)
        self.path = rng.choice(DROP_PATHS)
        self.hash = hashlib.sha256(f"{site}{rng.random()}".encode()).hexdigest()[:12]
        self.port = rng.choice([443, 8443, 445, 3389, 8080, 53])
        self.n_files = rng.choice([14, 47, 128, 812, 1204, 4812, 9317])
        self.gb = round(rng.uniform(0.2, 40.0), 1)
        self.days = rng.choice([3, 7, 11, 21, 46, 90])

    def by_role(self, *roles):
        for r in roles:
            for a in self.assets:
                if a["role"] == r:
                    return a
        return self.assets[0]

    def placeholders(self):
        wks = self.by_role("user_workstation")
        srv = self.by_role("file_server", "db_server", "backup_server", "mail_server")
        web = self.by_role("web_server", "db_server")
        dc = self.by_role("domain_controller", "file_server")
        return {
            "wks": wks["hostname"],
            "srv": srv["hostname"],
            "web": web["hostname"],
            "dc": dc["hostname"],
            "user": self.user,
            "svc": self.svc,
            "int_ip": wks["ip"],
            "ext_ip": self.ext_ip,
            "domain": self.domain,
            "file": self.file,
            "path": self.path,
            "hash": self.hash,
            "port": self.port,
            "n_files": f"{self.n_files:,}",
            "gb": self.gb,
            "days": self.days,
        }


def roles_for_record(rec, rng):
    """Derive asset roles from VERIS asset.assets[].variety (SCOPE.md 2.9)."""
    roles = []
    for a in (rec.get("asset") or {}).get("assets", []) or []:
        role = ROLE_BY_ASSET.get(a.get("variety"))
        if role and role not in roles:
            roles.append(role)
    # A blob needs somewhere for a user to be phished and somewhere to hold data.
    if "user_workstation" not in roles:
        roles.insert(0, "user_workstation")
    if len(roles) < 2:
        roles.append(rng.choice(["file_server", "db_server", "web_server"]))
    if len(roles) < 3 and rng.random() < 0.6:
        roles.append("domain_controller")
    return roles[:4]


def data_sensitivity(rec):
    conf = (rec.get("attribute") or {}).get("confidentiality") or {}
    for d in conf.get("data", []) or []:
        s = SENSITIVITY.get(d.get("variety"))
        if s:
            return s
    return "Internal"


def org_size(rec, rng):
    band = (rec.get("victim") or {}).get("employee_count")
    lo, hi = EMP_BANDS.get(band, (50, 5000))
    return rng.randint(lo, hi)


def incident_date(rec, rng):
    t = (rec.get("timeline") or {}).get("incident") or {}
    year = t.get("year") or 2020
    month = t.get("month") or rng.randint(1, 12)
    day = t.get("day") or rng.randint(1, 28)
    try:
        return datetime(int(year), int(month), min(int(day), 28))
    except (ValueError, TypeError):
        return datetime(2020, 1, 1)


def phase_gap_seconds(rec, rng):
    """Spacing between events, constrained by timeline.*.unit where VCDB has it.

    DATA_SURVEY.md 1.2: these are coarse duration buckets, not timestamps. They
    tell us how far apart events plausibly sat, nothing about what they were.
    """
    unit = ((rec.get("timeline") or {}).get("compromise") or {}).get("unit")
    scale = {
        "Seconds": (5, 90),
        "Minutes": (60, 900),
        "Hours": (900, 7200),
        "Days": (7200, 86400),
        "Weeks": (86400, 259200),
    }.get(unit, (120, 1800))
    return rng.randint(*scale)


def random_topological_order(nodes, edges, rng):
    """Kahn's algorithm, choosing randomly among all currently-available nodes.

    This is what stops the templater from emitting one fixed order per skeleton.
    The terminal node is held back and appended last (SCOPE.md 2.5 requires the
    detection alert to close the log).
    """
    refs = [n["ref"] for n in nodes]
    terminal = next((n["ref"] for n in nodes if n.get("terminal")), None)
    preds = {r: set() for r in refs}
    succs = {r: set() for r in refs}
    for a, b in edges:
        preds[b].add(a)
        succs[a].add(b)

    order, available = [], [r for r in refs if not preds[r] and r != terminal]
    remaining = dict(preds)
    while available:
        rng.shuffle(available)
        r = available.pop()
        order.append(r)
        for nxt in succs[r]:
            remaining[nxt] = remaining[nxt] - {r}
            if not remaining[nxt] and nxt != terminal and nxt not in order:
                available.append(nxt)
    if terminal:
        order.append(terminal)
    if len(order) != len(refs):  # cycle or unreachable node -- a chains.yaml bug
        raise ValueError(f"skeleton is not a DAG; ordered {len(order)} of {len(refs)}")
    return order


def build_events(skeleton, ents, noise_pool, rec, rng):
    """Ordered malicious events plus injected noise, with ascending timestamps."""
    by_ref = {n["ref"]: n for n in skeleton["nodes"]}
    order = random_topological_order(skeleton["nodes"], skeleton["edges"], rng)
    ph = ents.placeholders()

    rows = [
        {
            "event_type": by_ref[r]["event_type"],
            "desc": by_ref[r]["desc"].format(**ph),
            "noise": False,
            "ref": r,
        }
        for r in order
    ]

    # --- noise (TEMPLATING_DESIGN.md 4) ---------------------------------
    lo, hi = skeleton.get("noise", [1, 3])
    n_noise = rng.randint(lo, hi)
    for _ in range(n_noise):
        item = rng.choice(noise_pool)
        # Never after the terminal alert; otherwise anywhere.
        pos = rng.randint(0, max(0, len(rows) - 1))
        rows.insert(
            pos,
            {
                "event_type": item["event_type"],
                "desc": item["desc"].format(**ph),
                "noise": True,
                "ref": None,
            },
        )

    # --- timestamps -------------------------------------------------------
    t = incident_date(rec, rng) + timedelta(hours=rng.randint(0, 23), minutes=rng.randint(0, 59))
    for row in rows:
        row["ts"] = t
        t += timedelta(seconds=phase_gap_seconds(rec, rng))

    # --- endpoints --------------------------------------------------------
    hosts = [a["hostname"] for a in ents.assets]
    ip_of = {a["hostname"]: a["ip"] for a in ents.assets}
    for row in rows:
        host = next((h for h in hosts if h in row["desc"]), None) or rng.choice(hosts)
        row["src_host"] = host
        row["src_ip"] = ip_of.get(host, "-")
        if ents.ext_ip in row["desc"]:
            row["dst_ip"], row["dst_host"] = ents.ext_ip, "-"
        else:
            other = next((h for h in hosts if h in row["desc"] and h != host), None)
            row["dst_host"] = other or host
            row["dst_ip"] = ip_of.get(row["dst_host"], "-")
    return rows


def render(meta, assets, accounts, events, enrich):
    """Emit the blob exactly as SCOPE.md section 2 specifies."""
    L = ["=== TELEMETRY BLOB ==="]
    for k, v in meta.items():
        L.append(f"{k}: {v}")

    L.append("")
    L.append("--- ASSETS ---")
    L.append("asset_id | hostname | role | os | criticality | ip")
    for a in assets:
        L.append(
            " | ".join(
                [a["asset_id"], a["hostname"], a["role"], a["os"], a["criticality"], a["ip"]]
            )
        )

    L.append("")
    L.append("--- ACCOUNTS ---")
    L.append("account | type | privilege")
    for a in accounts:
        L.append(" | ".join([a["account"], a["type"], a["privilege"]]))

    L.append("")
    L.append("--- EVENTS ---")
    L.append("seq | timestamp | src_ip | dst_ip | src_host | dst_host | event_type | description")
    for i, e in enumerate(events, 1):
        L.append(
            " | ".join(
                [
                    str(i),
                    e["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"),
                    e["src_ip"],
                    e["dst_ip"],
                    e["src_host"],
                    e["dst_host"],
                    e["event_type"],
                    e["desc"],
                ]
            )
        )

    L.append("")
    L.append("--- ENRICHMENT ---")
    for k, v in enrich.items():
        L.append(f"{k}: {v}")
    L.append("=== END ===")
    return "\n".join(L)


def criticality(role, sens):
    if role == "domain_controller":
        return "critical"
    if role in ("file_server", "db_server", "backup_server", "mail_server", "hypervisor"):
        return "critical" if sens in ("PHI", "PCI", "Secrets") else "high"
    if role in ("web_server", "network_device"):
        return "high"
    return "medium"


class Templater:
    def __init__(self, tokenizer=None):
        doc = yaml.safe_load(CHAINS.read_text(encoding="utf-8"))
        self.noise_pool = doc["noise_pool"]
        self.by_technique = {}
        for s in doc["skeletons"]:
            self.by_technique.setdefault(s["technique"], []).append(s)
        self.tok = tokenizer
        self.fired = Counter()
        self.n_rendered = 0
        self.discarded = 0
        self.events_dropped = 0

    def n_tokens(self, text):
        if self.tok is None:
            return len(text) // 4
        return len(self.tok.encode(text))

    def build(self, rec, attack_id):
        rng = seeded_rng(rec.get("incident_id"))
        skeletons = self.by_technique.get(attack_id)
        if not skeletons:
            raise KeyError(f"no skeletons for {attack_id}")
        skeleton = rng.choice(skeletons)

        roles = roles_for_record(rec, rng)
        ents = Entities(rng, roles)
        sens = data_sensitivity(rec)

        assets = [{**a, "criticality": criticality(a["role"], sens)} for a in ents.assets]
        accounts = [
            {"account": ents.user, "type": "domain_user", "privilege": "standard"},
            {
                "account": ents.svc,
                "type": "service_account",
                "privilege": rng.choice(["local_admin", "standard"]),
            },
        ]
        events = build_events(skeleton, ents, self.noise_pool, rec, rng)[:MAX_EVENTS]

        vic = rec.get("victim") or {}
        meta = {
            "incident_id": f"INC-{incident_date(rec, rng).year}-"
            f"{str(rec.get('incident_id', ''))[:4].upper()}",
            "detected_at": events[-1]["ts"].strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reporting_tool": rng.choice(TOOLS),
            "org_industry": str(vic.get("industry", "unknown")),
            "org_size": org_size(rec, rng),
            "data_sensitivity": sens,
        }

        # analyst_notes comes from the skeleton, so it describes the control
        # failure THIS chain implies. Using the VCDB summary here instead put a
        # narrative about a different incident next to the events, which made
        # ## Root Cause underivable (DATA_SURVEY.md 3.5).
        notes = skeleton["notes"].format(**ents.placeholders())
        detections = [
            "Suspicious Process Lineage",
            "Bulk File Access Anomaly",
            "Outbound Volume Anomaly",
            "Authentication Anomaly",
        ]
        rng.shuffle(detections)
        enrich = {
            "detections": ", ".join(detections[:3]),
            "ioc_hashes": ents.hash,
            "external_ips": ents.ext_ip,
            "analyst_notes": notes,
        }

        blob, steps = self._fit(meta, assets, accounts, events, enrich)
        self.n_rendered += 1
        for s in steps:
            self.fired[s] += 1
        if blob is None:
            self.discarded += 1
        return {
            "blob": blob,
            "skeleton": skeleton["id"],
            "technique": attack_id,
            "n_events": len(events),
            "n_noise": sum(1 for e in events if e["noise"]),
            "event_types": [e["event_type"] for e in events],
            "truncation_steps": steps,
            "tokens": None if blob is None else self.n_tokens(blob),
        }

    def _fit(self, meta, assets, accounts, events, enrich):
        """Apply the SCOPE.md 2.7 ladder until the blob fits, or give up."""
        events = [dict(e) for e in events]
        enrich = dict(enrich)
        assets = [dict(a) for a in assets]
        steps = []

        blob = render(meta, assets, accounts, events, enrich)
        if self.n_tokens(blob) <= c.MAX_INPUT_TOKENS:
            return blob, steps

        # 1. trim descriptions to 20 words. Only counts as fired if it actually
        #    removed words -- most templated descriptions are already shorter,
        #    and recording a no-op as a fire makes the ladder stats meaningless.
        changed = False
        for e in events:
            words = e["desc"].split()
            if len(words) > 20:
                e["desc"] = " ".join(words[:20])
                changed = True
        if changed:
            steps.append(LADDER[0])
            blob = render(meta, assets, accounts, events, enrich)
            if self.n_tokens(blob) <= c.MAX_INPUT_TOKENS:
                return blob, steps

        # 2. drop events oldest-but-one first; keep seq 1 and the terminal alert
        while len(events) > 3:
            del events[1]
            self.events_dropped += 1
            if "2_drop_events" not in steps:
                steps.append(LADDER[1])
            blob = render(meta, assets, accounts, events, enrich)
            if self.n_tokens(blob) <= c.MAX_INPUT_TOKENS:
                return blob, steps

        # 3. drop detections, least specific first
        dets = [d.strip() for d in enrich["detections"].split(",") if d.strip()]
        while len(dets) > 1:
            dets.pop()
            enrich["detections"] = ", ".join(dets)
            if "3_drop_detections" not in steps:
                steps.append(LADDER[2])
            blob = render(meta, assets, accounts, events, enrich)
            if self.n_tokens(blob) <= c.MAX_INPUT_TOKENS:
                return blob, steps

        # 4. drop assets not referenced by a surviving event, lowest criticality first
        rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        referenced = {e["src_host"] for e in events} | {e["dst_host"] for e in events}
        droppable = sorted(
            (a for a in assets if a["hostname"] not in referenced),
            key=lambda a: rank.get(a["criticality"], 1),
        )
        for a in droppable:
            if len(assets) <= 1:
                break
            assets.remove(a)
            if "4_drop_assets" not in steps:
                steps.append(LADDER[3])
            blob = render(meta, assets, accounts, events, enrich)
            if self.n_tokens(blob) <= c.MAX_INPUT_TOKENS:
                return blob, steps

        # 5. analyst_notes -- last resort. Usually the only field that makes
        #    Root Cause derivable, so losing it forces the SCOPE.md 3.5 fallback.
        if enrich.get("analyst_notes") not in (None, "-"):
            enrich["analyst_notes"] = "-"
            steps.append(LADDER[4])
            blob = render(meta, assets, accounts, events, enrich)
            if self.n_tokens(blob) <= c.MAX_INPUT_TOKENS:
                return blob, steps

        return None, steps  # over budget after the full ladder -- discard


def load_tokenizer():
    try:
        from transformers import AutoTokenizer

        return AutoTokenizer.from_pretrained(c.BASE_MODEL)
    except Exception as exc:  # noqa: BLE001 - offline is a normal condition here
        print(
            f"WARNING: Qwen tokenizer unavailable ({exc}); using a char/4 estimate. "
            f"Token counts below are NOT authoritative.",
            file=sys.stderr,
        )
        return None


def main():
    """Render every selected record and report truncation-step fire rates."""
    from src.label_coverage import load_records

    sel = [
        json.loads(line)
        for line in (c.PROCESSED / "selected.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    wanted = {s["incident_id"]: s for s in sel}
    records = {r.get("incident_id"): r for r in load_records()}

    t = Templater(load_tokenizer())
    out = c.PROCESSED / "blobs.jsonl"
    with out.open("w", encoding="utf-8") as fh:
        for iid, s in wanted.items():
            rec = records.get(iid)
            if rec is None:
                continue
            res = t.build(rec, s["attack_id"])
            res["incident_id"] = iid
            res["split"] = s["split"]
            fh.write(json.dumps(res) + "\n")

    print(f"rendered {t.n_rendered:,} blobs, discarded {t.discarded}")
    print("\ntruncation ladder fire rates:")
    for step in LADDER:
        n = t.fired[step]
        print(f"  {step:24s} {n:5d}  {100.0 * n / max(1, t.n_rendered):5.1f}%")
    if t.fired["2_drop_events"]:
        print(
            f"\n  event rows removed by step 2: {t.events_dropped:,} total, "
            f"{t.events_dropped / t.fired['2_drop_events']:.1f} per affected blob"
        )
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
