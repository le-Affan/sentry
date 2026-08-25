# SCOPE — Telemetry-to-Incident-Report Fine-Tune

## 1. Project Statement

This project fine-tunes a small open-weight language model to convert raw security
telemetry into a structured, analyst-readable incident report. The model receives a
single flat text blob resembling what a SIEM exports for one incident — incident
metadata, an asset inventory, an account list, a time-ordered event log, and detection
enrichment — and emits a fixed six-section Markdown report covering summary, affected
assets, attack technique, severity, root cause, and recommended actions. The work is
strictly defensive and academic: it summarizes and classifies incidents that already
happened, and produces no offensive capability. The training spine is the VERIS
Community Database (VCDB), which supplies real, de-identified incident records; the
MITRE ATT&CK corpus is used as a retrieval source at inference time so the model can
ground technique attribution in canonical technique descriptions rather than memory.
Success is defined as a model that produces parseable, well-grounded reports whose
technique ID and severity label can be scored automatically against ground truth.

---

## 2. INPUT SPEC

### 2.1 Shape

One incident = one plain-text blob. Five blocks, always in this order, always present.
A block with no rows still emits its header and the literal line `(none)`. Field order
inside a block is fixed. The delimiter is ` | ` (space-pipe-space). All timestamps are
ISO-8601 UTC with a `Z` suffix. Events are sorted ascending by `timestamp`.

```
=== TELEMETRY BLOB ===     <metadata lines>
--- ASSETS ---             <header row> <asset rows>
--- ACCOUNTS ---           <header row> <account rows>
--- EVENTS ---             <header row> <event rows>
--- ENRICHMENT ---         <enrichment lines>
=== END ===
```
(Each block header sits on its own line; rows follow it, one per line; a blank line
separates blocks.)

### 2.2 Block: metadata

`key: value`, one per line, fixed order.

| Field | Type | Example |
|---|---|---|
| `incident_id` | string | `INC-2024-0417` |
| `detected_at` | ISO-8601 UTC | `2024-04-17T02:14:33Z` |
| `reporting_tool` | string | `Splunk ES` |
| `org_industry` | string | `Healthcare` |
| `org_size` | int (headcount) | `1200` |
| `data_sensitivity` | enum: `Public` / `Internal` / `PII` / `PHI` / `PCI` / `Secrets` | `PHI` |

### 2.3 Block: ASSETS

Header row: `asset_id | hostname | role | os | criticality | ip`

| Field | Notes |
|---|---|
| `asset_id` | `A-###`, unique in blob |
| `hostname` | uppercase, e.g. `HQ-SRV-DC02` |
| `role` | enum: `user_workstation`, `file_server`, `domain_controller`, `web_server`, `db_server`, `mail_server`, `hypervisor`, `network_device`, `backup_server` |
| `os` | free text |
| `criticality` | enum: `low`, `medium`, `high`, `critical` |
| `ip` | IPv4, RFC 5737 ranges only |

### 2.4 Block: ACCOUNTS

Header row: `account | type | privilege`

| Field | Notes |
|---|---|
| `account` | `DOMAIN\user` or `user@domain` |
| `type` | enum: `domain_user`, `local_user`, `service_account`, `admin_account`, `external` |
| `privilege` | enum: `standard`, `local_admin`, `domain_admin`, `unknown` |

### 2.5 Block: EVENTS

Header row: `seq | timestamp | src_ip | dst_ip | src_host | dst_host | event_type | description`

| Field | Notes |
|---|---|
| `seq` | int, 1..N, contiguous |
| `timestamp` | ISO-8601 UTC |
| `src_ip` / `dst_ip` | IPv4 or `-` if not applicable |
| `src_host` / `dst_host` | hostname from ASSETS, or an external label, or `-` |
| `event_type` | enum: `email_delivery`, `process_create`, `file_write`, `file_read`, `auth_success`, `auth_failure`, `net_connection`, `dns_query`, `registry_write`, `service_install`, `priv_escalation`, `data_transfer`, `alert` |
| `description` | one sentence, ≤ 30 words, no newlines |

Event count is capped at 12 rows to hold the token budget.

### 2.6 Block: ENRICHMENT

`key: value`, one per line, fixed order.

| Field | Notes |
|---|---|
| `detections` | comma-separated detection rule names fired |
| `ioc_hashes` | comma-separated SHA-256 prefixes (12 chars) or `-` |
| `external_ips` | comma-separated non-internal IPs seen |
| `analyst_notes` | one sentence of triage context, or `-` |

### 2.7 Token budget

Hard constraint: **the rendered blob must fit in ~700 tokens.** The dataset builder
truncates to satisfy this in fixed priority order, cheapest loss first:

1. Trim event `description` fields to 20 words.
2. Drop EVENTS rows, oldest-but-one first — always keep `seq 1` (initial access) and
   the final `alert` row (detection outcome), and work inward from the second-oldest.
3. Drop `detections` entries from ENRICHMENT, least-specific first.
4. Drop asset rows, lowest `criticality` first, and only assets not referenced by any
   surviving event.
5. Drop `analyst_notes` — **last resort only.**

`analyst_notes` is dropped last because it is usually the only field that makes
`## Root Cause` derivable; losing it forces the "insufficient evidence" fallback in
§3.5. A blob that needs step 5 to fit is flagged `truncated_to_notes = True` so the
share of such records is visible at dataset-build time. Any blob still over budget
after all five passes is discarded rather than silently clipped.

### 2.8 Worked input example

```
=== TELEMETRY BLOB ===
incident_id: INC-2024-0417
detected_at: 2024-04-17T02:14:33Z
reporting_tool: Splunk ES
org_industry: Healthcare
org_size: 1200
data_sensitivity: PHI

--- ASSETS ---
asset_id | hostname | role | os | criticality | ip
A-001 | HQ-WKS-2291 | user_workstation | Windows 10 22H2 | medium | 10.14.6.31
A-002 | HQ-SRV-FS01 | file_server | Windows Server 2019 | high | 10.14.2.10
A-003 | HQ-SRV-DC02 | domain_controller | Windows Server 2019 | critical | 10.14.2.4

--- ACCOUNTS ---
account | type | privilege
CORP\j.reyes | domain_user | standard
CORP\svc_backup | service_account | local_admin

--- EVENTS ---
seq | timestamp | src_ip | dst_ip | src_host | dst_host | event_type | description
1 | 2024-04-17T01:52:08Z | 203.0.113.44 | 10.14.6.31 | ext-mail-gw | HQ-WKS-2291 | email_delivery | Inbound message with attachment Invoice_Q1_overdue.xlsm delivered to CORP\j.reyes from billing@vendor-invoices.example
2 | 2024-04-17T01:54:41Z | - | - | HQ-WKS-2291 | HQ-WKS-2291 | process_create | EXCEL.EXE spawned powershell.exe with encoded command argument
3 | 2024-04-17T01:54:58Z | 10.14.6.31 | 203.0.113.44 | HQ-WKS-2291 | - | net_connection | Outbound HTTPS from powershell.exe to 203.0.113.44 on port 443
4 | 2024-04-17T01:55:12Z | - | - | HQ-WKS-2291 | HQ-WKS-2291 | file_write | powershell.exe wrote C:\Users\Public\svcupd.exe hash a91f3c07be22
5 | 2024-04-17T01:57:03Z | - | - | HQ-WKS-2291 | HQ-WKS-2291 | service_install | New service SvcUpdater created pointing to C:\Users\Public\svcupd.exe
6 | 2024-04-17T02:03:19Z | 10.14.6.31 | 10.14.2.10 | HQ-WKS-2291 | HQ-SRV-FS01 | auth_success | SMB session established to HQ-SRV-FS01 using CORP\svc_backup credentials
7 | 2024-04-17T02:05:44Z | 10.14.6.31 | 10.14.2.10 | HQ-WKS-2291 | HQ-SRV-FS01 | file_read | 4,812 files read from share \\HQ-SRV-FS01\PatientRecords over 90 seconds
8 | 2024-04-17T02:09:27Z | 10.14.2.10 | 203.0.113.44 | HQ-SRV-FS01 | - | data_transfer | 2.7 GB uploaded to 203.0.113.44 over HTTPS
9 | 2024-04-17T02:11:50Z | 10.14.6.31 | 10.14.2.4 | HQ-WKS-2291 | HQ-SRV-DC02 | auth_failure | 14 failed logon attempts for CORP\svc_backup against HQ-SRV-DC02
10 | 2024-04-17T02:14:33Z | - | - | HQ-SRV-FS01 | - | alert | DLP rule flagged bulk PHI egress from HQ-SRV-FS01

--- ENRICHMENT ---
detections: Suspicious Office Child Process, Bulk File Access Anomaly, DLP-PHI-Egress
ioc_hashes: a91f3c07be22
external_ips: 203.0.113.44
analyst_notes: Attachment macro was not blocked; workstation macro policy set to prompt-user.
=== END ===
```


### 2.9 Field provenance

Where each input field actually comes from. Marks: **VCDB** (direct from a VERIS
record), **DERIVED** (computed or mapped from VCDB fields), **SYNTHETIC** (invented by
our templating code).

| Block | Field | Provenance | Note |
|---|---|---|---|
| metadata | `incident_id` | **VCDB** | VERIS `incident_id` (UUID); reformatted to `INC-YYYY-NNNN` for readability |
| metadata | `detected_at` | **DERIVED** | Date from `timeline.incident` (43.4% have day-level; 28.9% month-only, 27.7% year-only). Time-of-day is synthetic — only 10/10,596 records carry a clock time |
| metadata | `reporting_tool` | **SYNTHETIC** | Not in VERIS; sampled from a fixed tool list |
| metadata | `org_industry` | **VCDB** | `victim.industry` (NAICS), 100% present; mapped NAICS → label |
| metadata | `org_size` | **DERIVED** | `victim.employee_count` is a band (`Over 100000`); 72.8% informative. Rendered as a point value sampled inside the band |
| metadata | `data_sensitivity` | **DERIVED** | From `attribute.confidentiality.data[].variety` (e.g. Medical → `PHI`, Payment → `PCI`) |
| ASSETS | `asset_id` | **SYNTHETIC** | Sequence number assigned at render time |
| ASSETS | `hostname` | **SYNTHETIC** | VERIS has no named machines. 3/10,596 records contain anything hostname-shaped |
| ASSETS | `role` | **DERIVED** | `asset.assets[].variety` (88 values, e.g. `S - Database`) mapped to our role enum |
| ASSETS | `os` | **SYNTHETIC** | Not in VERIS; sampled consistently with the mapped role |
| ASSETS | `criticality` | **DERIVED** | From asset variety class (`S -` server, `U -` user device) plus `data_sensitivity` |
| ASSETS | `ip` | **SYNTHETIC** | 4/10,596 records contain an IPv4, all incidental mentions in free text |
| ACCOUNTS | `account` | **SYNTHETIC** | VERIS names no accounts |
| ACCOUNTS | `type` | **DERIVED** | From `actor.{internal,external,partner}` and `actor.*.variety` |
| ACCOUNTS | `privilege` | **DERIVED** | From `action.misuse.variety` / `actor.internal.variety` (e.g. `Privilege abuse`, `System admin`) |
| EVENTS | `seq` | **SYNTHETIC** | Ordering is our construction |
| EVENTS | `timestamp` | **SYNTHETIC** | Anchored to the VCDB incident date, but per-event offsets are invented. Spacing constrained by `timeline.{compromise,exfiltration,discovery}.unit` where present (11–26% of records) |
| EVENTS | `src_ip` / `dst_ip` | **SYNTHETIC** | See ASSETS `ip` |
| EVENTS | `src_host` / `dst_host` | **SYNTHETIC** | See ASSETS `hostname` |
| EVENTS | `event_type` | **DERIVED** | Chain skeleton selected by `action.*.variety`; the individual row assignment is ours |
| EVENTS | `description` | **SYNTHETIC** | Templated text. Wording may draw on `summary`, but no VERIS field contains event descriptions |
| ENRICHMENT | `detections` | **SYNTHETIC** | Rule names invented; loosely informed by `discovery_method` |
| ENRICHMENT | `ioc_hashes` | **SYNTHETIC** | 6/10,596 records contain a hash, all incidental |
| ENRICHMENT | `external_ips` | **SYNTHETIC** | See ASSETS `ip` |
| ENRICHMENT | `analyst_notes` | **DERIVED** | Condensed from VERIS `summary` (95.1% present, median 24 words) plus `action.*.vector` and `control_failure` where present. The one field carrying real human narrative |

**Tally: 6 VCDB/DERIVED-from-real-facts in metadata, 4 DERIVED in ASSETS/ACCOUNTS, and
effectively the entire EVENTS block synthetic.** See `docs/DATA_SURVEY.md` §3 for the
measurements behind each mark, and §3.3 for why the shipped VERIS→ATT&CK crosswalk
cannot supply ground-truth technique labels.


---

## 3. OUTPUT SPEC

Sectioned Markdown. Exactly six `##` headings, exactly this spelling, exactly this
order, no other headings, no preamble text before `## Summary`, no trailing text after
the last bullet. Blank line between each section.

The six headings are, verbatim: `## Summary`, `## Affected Assets`,
`## Attack Technique`, `## Severity`, `## Root Cause`, `## Recommended Actions`.

### 3.1 `## Summary`

- **Content:** what happened, in what order, and what the outcome was. Plain prose.
- **Length:** 2–4 sentences, 40–90 words.
- **Constraints:** must name at least one asset and the initial access vector. No
  bullets. No speculation about actor identity or attribution to a named group.

### 3.2 `## Affected Assets`

- **Content:** one bullet per asset touched by the incident.
- **Format:** `- <hostname> (<role>) — <what happened to it>`
- **Length:** 1–6 bullets, each ≤ 20 words.
- **Constraints:** every hostname must appear verbatim in the input ASSETS block.
  Assets present in the input but not involved in any event are omitted.

### 3.3 `## Attack Technique`

- **Content:** the primary MITRE ATT&CK technique, as ID plus name.
- **Format:** `<Txxxx[.yyy]> — <Technique Name>` on the first line, then one sentence
  (≤ 30 words) justifying the mapping against a specific event.
- **Allowed values:** any valid MITRE ATT&CK Enterprise technique or sub-technique ID
  matching `T\d{4}(\.\d{3})?`. The name must match the canonical ATT&CK name for that
  ID exactly.
- **Constraints:** exactly one technique ID in this section. Secondary techniques, if
  worth noting, belong in `## Summary` as prose, not here — the ID on this line is the
  one that gets scored.

### 3.4 `## Severity`

- **Content:** a single label plus a one-sentence rationale.
- **Format:** `<Label> — <rationale, ≤ 25 words>`
- **Allowed values (exactly one of):** `Low`, `Medium`, `High`, `Critical`.
- **Rubric used to label training data:**

| Label | Condition |
|---|---|
| `Low` | Attempt blocked or failed; no asset compromised; no data accessed. |
| `Medium` | Single non-critical asset compromised; no sensitive data accessed; no lateral movement. |
| `High` | Lateral movement occurred, or a `high`-criticality asset compromised, or sensitive data accessed without confirmed egress. |
| `Critical` | Confirmed egress of sensitive data, or `critical`-criticality asset (e.g. domain controller) compromised, or org-wide availability loss. |

### 3.5 `## Root Cause`

- **Content:** the control failure that made the incident possible — not a restatement
  of the attack chain.
- **Length:** 1–3 sentences, 25–60 words.
- **Constraints:** must be traceable to something observable in the input (an event, an
  account privilege, an enrichment note). If the input does not support a root cause,
  the required output is the literal sentence
  `Insufficient evidence in the available telemetry to determine root cause.`

### 3.6 `## Recommended Actions`

- **Content:** defensive remediation and hardening steps.
- **Format:** numbered list, `1.` … `N.`, each starting with an imperative verb.
- **Length:** 3–6 items, each ≤ 25 words.
- **Constraints:** ordered most-urgent first — containment before eradication before
  hardening. Each item must be actionable by a defender. No offensive actions, no
  "hack back", no vendor product names.

### 3.7 Worked output example

Pairs with the input example in §2.8.

```
## Summary
On 2024-04-17, a user on HQ-WKS-2291 opened a macro-enabled attachment that launched
PowerShell and dropped a persistent binary. The attacker then authenticated to
HQ-SRV-FS01 with the svc_backup service account, read 4,812 files from the
PatientRecords share, and uploaded 2.7 GB to an external host. Follow-on attempts
against the domain controller HQ-SRV-DC02 failed.

## Affected Assets
- HQ-WKS-2291 (user_workstation) — initial compromise; malicious binary and persistent service installed.
- HQ-SRV-FS01 (file_server) — accessed via svc_backup; bulk PHI read and exfiltrated.
- HQ-SRV-DC02 (domain_controller) — targeted by 14 failed logons; no successful access observed.

## Attack Technique
T1566.001 — Phishing: Spearphishing Attachment
Event 1 delivered a macro-enabled attachment that directly precedes the Excel-spawned
PowerShell execution in event 2.

## Severity
Critical — 2.7 GB of PHI was confirmed exfiltrated to an external host after lateral movement.

## Root Cause
Workstation macro policy was set to prompt-user rather than block, allowing Office to
execute attacker macro code. A local-admin service account, svc_backup, was usable from
a standard workstation, which turned a single endpoint compromise into file server access.

## Recommended Actions
1. Isolate HQ-WKS-2291 and HQ-SRV-FS01 from the network and preserve volatile memory.
2. Disable the CORP\svc_backup account and rotate its credentials domain-wide.
3. Remove the SvcUpdater service and the binary at C:\Users\Public\svcupd.exe.
4. Block 203.0.113.44 at the perimeter and hunt for other hosts contacting it.
5. Enforce a block-by-default macro policy for files originating from the internet.
6. Scope the PHI exposure from the PatientRecords share and start breach notification review.
```

---

## 4. PARSING RULES

Generated text is parsed with regex into a six-key dict before scoring. Parsing runs on
the raw decode with no manual cleanup, so a parse failure is a model failure and is
recorded as such.

### 4.1 Section splitting

Split on headings, capturing each body up to the next heading or end of string, with
`re.DOTALL | re.MULTILINE`:

```
^##[ ]+Summary\s*\n(?P<summary>.*?)(?=^##[ ]+|\Z)
^##[ ]+Affected[ ]Assets\s*\n(?P<assets>.*?)(?=^##[ ]+|\Z)
^##[ ]+Attack[ ]Technique\s*\n(?P<technique>.*?)(?=^##[ ]+|\Z)
^##[ ]+Severity\s*\n(?P<severity>.*?)(?=^##[ ]+|\Z)
^##[ ]+Root[ ]Cause\s*\n(?P<root_cause>.*?)(?=^##[ ]+|\Z)
^##[ ]+Recommended[ ]Actions\s*\n(?P<actions>.*?)(?=^##[ ]+|\Z)
```

A generation missing any of the six named groups is marked `format_valid = False` and
scores 0 on technique accuracy and severity accuracy. It still receives ROUGE-L and
BERTScore on whatever text was produced.

### 4.2 Attack Technique extraction

```
technique_id:   \bT(?P<num>\d{4})(?:\.(?P<sub>\d{3}))?\b
technique_name: ^\s*T\d{4}(?:\.\d{3})?\s*[—\-–:]\s*(?P<name>.+?)\s*$
```

Rules:
- Search the `technique` group only; never the whole document.
- Take the **first** match. If more than one distinct ID matches, set
  `technique_multi = True` — the first is still scored, and the flag is reported as a
  spec violation rate.
- Normalize to uppercase `T` and strip whitespace; `t1566.1` is not accepted as
  `T1566.001` — the sub-technique must be three digits.
- Name comparison is case-insensitive and whitespace-normalized; the em dash, en dash,
  hyphen, and colon are all accepted as the separator.
- ID and name are scored separately, so a right ID with a wrong name is visible.

### 4.3 Severity extraction

```
^\s*(?P<severity>Low|Medium|High|Critical)\b
```

Rules:
- Anchored to the start of the `severity` section body, case-insensitive, first match
  only. This prevents a rationale like "…higher than a Low-severity scan…" from
  overriding the label.
- Normalized to title case.
- No match, or a word outside the four allowed labels, yields `severity = None` and
  counts as incorrect.

### 4.4 Affected assets extraction

```
^-\s+(?P<hostname>[A-Z0-9][A-Z0-9\-]+)\s+\((?P<role>[a-z_]+)\)\s*[—\-–]\s*(?P<note>.+)$
```

Applied per line with `re.MULTILINE`. Hostnames feed the grounding score.

### 4.5 Recommended actions extraction

```
^\s*(?P<n>\d+)\.\s+(?P<action>.+)$
```

Item count is checked against the 3–6 range from §3.6.

### 4.6 Entity extraction for grounding

The same patterns run over both the input blob and the generated report; the grounding
score is the fraction of output entities absent from the input.

```
ipv4:     \b(?:\d{1,3}\.){3}\d{1,3}\b
hostname: \b[A-Z]{2,}-[A-Z0-9]{2,}-[A-Z0-9]{2,}\b
account:  \b[A-Z]+\\[a-zA-Z0-9._\-]+\b
path:     \b[A-Za-z]:\\[^\s,;"']+
hash:     \b[a-f0-9]{12,64}\b
```

---

## 5. EVALUATION PLAN

Metrics only. No implementation in this phase.

| # | Metric | Applied to | Reported as |
|---|---|---|---|
| 1 | **ROUGE-L** | Full report, and per section | F1, mean over test set |
| 2 | **BERTScore** | Full report, and per section | F1, mean over test set |
| 3 | **Technique-ID accuracy** | `## Attack Technique` | Exact-match rate; also reported tactic-level (parent technique) and top-3 confusion pairs |
| 4 | **Severity accuracy** | `## Severity` | Exact-match rate; plus 4×4 confusion matrix and off-by-one-adjacent rate |
| 5 | **Grounding score** | Whole report | Fraction of extracted output entities (IPs, hostnames, accounts, paths, hashes) not present in the input blob — lower is better |
| 6 | **Manual rubric** | Stratified sample of test outputs | Human 1–5 scores on factual accuracy, completeness, actionability of recommendations, and format compliance |

Supporting counters reported alongside: parse success rate, `technique_multi` violation
rate, section-length spec violation rate. All six are computed for the untrained base model (baseline), the fine-tuned model, and
the fine-tuned model with RAG, on the same held-out test split.

---

## 6. FIXED CONSTRAINTS

Non-negotiable for the remainder of the project. Changing any of these requires an
explicit scope revision, not an in-flight decision.

| Constraint | Value |
|---|---|
| Base model | `Qwen2.5-3B-Instruct` |
| Fine-tuning method | 4-bit QLoRA |
| `max_seq_len` | 1024 |
| Dataset size | ~900 train / 100 test pairs |
| Training runs | Single training run — no hyperparameter sweep, no retraining |
| Compute | Kaggle GPU |
| Data spine | VERIS Community Database (VCDB) |
| RAG corpus | MITRE ATT&CK Enterprise, used for retrieval at inference only |
| Posture | Defensive analysis only |

Notes on the consequences of these constraints, so they are not relitigated later:

- `max_seq_len 1024` is why the input blob is capped at ~700 tokens (§2.7) and the
  output spec caps section lengths (§3) — input plus output must fit one sequence.
- A single training run means the baseline evaluation must be run *before* training, as
  there is no budget to redo it.
- ATT&CK is a retrieval corpus, not training data. Technique text is not fine-tuned into
  the model, so technique-ID accuracy is expected to be the metric most improved by RAG.
- VCDB records are the source of ground-truth severity and technique labels; where a
  VCDB record lacks an ATT&CK mapping, the record is excluded rather than guessed.
