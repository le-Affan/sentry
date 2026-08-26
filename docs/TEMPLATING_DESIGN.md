<!-- Last updated 2026-08-27. The section 6.3 leakage test FAILED; see section 7.1 and LIMITATIONS.md. -->
# TEMPLATING DESIGN

Design only. No generator code exists yet. This document decides how synthetic
telemetry blobs are constructed before any are built, because the construction choices
determine what the trained model can possibly learn.

---

## 1. The problem this document exists to solve

`DATA_SURVEY.md` §3.2 established that VCDB supplies no telemetry: every EVENTS row,
hostname, IP, path, and hash in a blob is invented by us. `LABEL_COVERAGE.md`
established that the technique label is derived from `action.*.variety`.

Those two facts collide:

```
                    VCDB action.variety
                        /          \
                       /            \
            event-chain skeleton   technique label
                       \            /
                        \          /
                    the model's task
```

**The input and the target are generated from the same variable.** A naive templater
that emits one fixed chain per variety makes every `T1486` blob structurally identical.
The model then does not need to read the telemetry at all — it can recognise the
skeleton and emit the matching technique. It would score well on technique accuracy
while performing no analysis whatsoever, and we would have measured our own generator.

This is not a hypothetical risk. It is the default outcome of the obvious
implementation, and with a single training run (SCOPE.md §6) there is no second attempt
to notice and correct it.

The rest of this document specifies four mechanisms to break the shortcut, and then
states plainly what remains broken afterwards.

---

## 2. Mechanism 1 — at least three chain skeletons per technique

Each technique gets **no fewer than three structurally distinct event chains**. Distinct
means different length, different event-type sequence, and different narrative shape —
not the same chain with different hostnames.

Skeleton choice is randomised per record, seeded from the VCDB `incident_id` so
generation is reproducible.

### 2.1 T1486 — Data Encrypted for Impact

| # | Name | Chain | Length |
|---|---|---|---|
| A | Phish-to-encrypt | `email_delivery` → `process_create` → `net_connection` → `file_write` → `service_install` → `file_write`(bulk) → `alert` | 7 |
| B | Edge-exploit-to-encrypt | `alert`(IDS) → `net_connection` → `process_create` → `auth_success` → `net_connection`(lateral) → `file_write`(bulk) → `alert` | 7 |
| C | Slow-burn ransomware | `auth_success`(VPN) → `dns_query` → `process_create` → `registry_write` → *(gap of days)* → `service_install` → `file_write`(bulk) → `alert` | 8 |
| D | Backup-first | `auth_success` → `process_create` → `file_read`(backup share) → `file_write`(deletion) → `file_write`(bulk) → `alert` | 6 |

Note that C carries a multi-day gap and D opens on a credentialed login with no delivery
event at all. A model keying on "first row is `email_delivery`" fails on both.

### 2.2 T1566 — Phishing

| # | Name | Chain | Length |
|---|---|---|---|
| A | Attachment macro | `email_delivery` → `process_create` → `net_connection` → `file_write` → `alert` | 5 |
| B | Credential harvest page | `email_delivery` → `dns_query` → `net_connection` → `auth_success`(from new geo) → `alert` | 5 |
| C | Reported, not clicked | `email_delivery` → `alert`(user report) → `email_delivery`(second wave) → `alert` | 4 |
| D | Thread hijack | `email_delivery`(internal sender) → `process_create` → `auth_failure` → `auth_success` → `alert` | 5 |

Skeleton C is deliberately an *unsuccessful* phishing incident. Without it every
phishing blob would imply compromise, and severity would become perfectly predictable
from the technique.

### 2.3 T1190 — Exploit Public-Facing Application

| # | Name | Chain | Length |
|---|---|---|---|
| A | Web shell | `net_connection`(anomalous request) → `file_write`(web root) → `process_create` → `net_connection` → `alert` | 5 |
| B | Injection to data read | `net_connection` → `alert`(WAF) → `net_connection` → `file_read`(bulk) → `data_transfer` → `alert` | 6 |
| C | Exploit to lateral | `net_connection` → `process_create` → `auth_success` → `net_connection`(internal) → `auth_failure` → `alert` | 6 |
| D | Scanned then hit | `net_connection`(scan) → `net_connection`(scan) → `net_connection`(exploit) → `process_create` → `alert` | 5 |

### 2.4 T1078 — Valid Accounts

| # | Name | Chain | Length |
|---|---|---|---|
| A | Impossible travel | `auth_success`(foreign IP) → `auth_success` → `file_read` → `data_transfer` → `alert` | 5 |
| B | Service account abuse | `auth_success`(service acct, interactive) → `net_connection` → `file_read` → `alert` | 4 |
| C | Dormant account revival | `auth_success`(90-day dormant) → `registry_write` → `auth_success`(second host) → `file_read` → `alert` | 5 |
| D | Credential stuffing survivor | `auth_failure` ×N → `auth_success` → `auth_success` → `alert` | 5 |

Skeleton D deliberately overlaps T1110's shape. See §3.

### 2.5 T1498 — Network Denial of Service

| # | Name | Chain | Length |
|---|---|---|---|
| A | Volumetric flood | `net_connection`(volume spike) → `alert` → `net_connection` → `alert`(availability) | 4 |
| B | Application-layer | `net_connection` ×N(same endpoint) → `alert`(latency) → `alert` | 4 |
| C | DoS as cover | `net_connection`(flood) → `alert` → `auth_success` → `file_read` → `alert` | 5 |

Skeleton C is a DoS used to mask an intrusion — the correct primary technique is still
arguable, and it is included precisely because it is hard.

### 2.6 Remaining techniques

Techniques below the top five carry fewer records (see `LABEL_COVERAGE.md` §3) but the
three-skeleton minimum still applies: `T1110`, `T1598`, `T1071`, `T1005`, `T1056.001`,
`T1041`, `T1485`, `T1105`, `T1003`. Their skeletons are specified in the generator
alongside the five above; the design rule, not the enumeration, is what matters here.

**Total: no fewer than 3 skeletons × 14 techniques = 42 distinct chains**, with 4 each
for the five dominant techniques.

---

## 3. Mechanism 2 — a shared event-type vocabulary

The `event_type` enum in SCOPE.md §2.5 is deliberately **not** technique-specific. There
is no `ransomware_encrypt` value and no `phishing_click` value. Every chain draws from
the same 13 types.

The design rule is that **every event type must appear in chains for at least three
different techniques.** Concretely:

| Event type | Appears in |
|---|---|
| `auth_success` | T1078, T1486, T1190, T1110, T1498 |
| `net_connection` | T1190, T1498, T1486, T1071, T1041 |
| `file_read` | T1078, T1190, T1005, T1041 |
| `process_create` | T1486, T1566, T1190, T1105 |
| `file_write` | T1486, T1190, T1105, T1485 |
| `email_delivery` | T1566, T1598, T1486 |
| `alert` | all |

This removes the possibility of a one-to-one event-type-to-technique lookup. A blob
containing `file_write` could be ransomware, a web shell, a tool transfer, or data
destruction; only the surrounding sequence and content distinguish them.

**Anti-rule:** if any event type ends up appearing in chains for only one technique, that
is a design bug to be fixed by adding chains, not accepted.

---

## 4. Mechanism 3 — benign and noise events

Each chain is padded with **1–3 benign events** drawn from a shared pool, inserted at
random positions among the malicious rows subject to the ordering constraints in §5.

Noise pool, none of which indicate compromise:

- Routine `auth_success` for an unrelated user on an unrelated host
- Scheduled `service_install` from a legitimate patch cycle
- `dns_query` to a well-known SaaS domain
- `net_connection` to an internal update server
- `file_read` from a user's own home directory
- `auth_failure` from a mistyped password, followed by a success minutes later
- `alert` from a rule that fired and was later dispositioned benign

Two consequences, both intended:

1. **Event count stops being a technique signal.** Without noise, chain length correlates
   with technique. With 1–3 random additions, the length distributions overlap.
2. **The report must select, not transcribe.** `## Affected Assets` and `## Summary` are
   scored against a reference that mentions only the genuinely involved assets. A model
   that lists every host in the blob loses ROUGE-L and grounding, so noise creates real
   discrimination work.

The noise ratio is capped at 3 events so blobs stay inside the ~700-token budget
(SCOPE.md §2.7), and noise rows are the first thing the truncation ladder drops.

---

## 5. Mechanism 4 — randomised ordering where causally valid

Events are **not** emitted in a fixed template order. Each skeleton declares a partial
order — a dependency graph — and the generator emits any valid topological sort.

Causal constraints that always hold:

- Delivery precedes execution (`email_delivery` before the `process_create` it caused).
- Execution precedes what it produced (`process_create` before its `file_write`).
- Access precedes use (`auth_success` before the `file_read` on that host).
- Exfiltration follows collection (`file_read` before `data_transfer`).
- The terminating `alert` is last.

Everything else is free to move. Independent branches — a `dns_query` and an unrelated
`auth_success`, a noise event and any malicious row — are shuffled. Inter-event time
gaps are sampled rather than fixed, constrained by `timeline.*.unit` where VCDB records
it (`DATA_SURVEY.md` §1.2).

**Deliberately preserved:** `seq` is always contiguous and `timestamp` always ascending,
per SCOPE.md §2.5. The randomisation is in which events occupy which positions, not in
whether the log is well-formed. A malformed log would test parsing robustness, which is
not what this project measures.

---

## 6. Verification before generating the pairs

The mechanisms above are claims, and claims about a generator can be checked. Before the
full build, generate a pilot of ~100 blobs and confirm:

1. **Skeleton uniformity.** No skeleton exceeds 40% of the blobs for its technique.
2. **Length overlap.** Event-count distributions for the top five techniques overlap;
   no technique is separable by length alone.
3. **The leakage test — the one that matters.** Train a trivial classifier (bag of
   `event_type` n-grams, logistic regression) to predict the technique from the blob
   with all description text removed. If it scores far above the majority-class
   baseline, the structure alone leaks the label and the skeletons need more mixing.
   This is cheap, runs in seconds, and is the direct measurement of the problem in §1.
4. **Noise survives.** Benign events appear in ≥90% of blobs after truncation.
5. **Held-out hand-written blobs.** Reserve 10–15 test blobs written by hand rather than
   generated, so at least part of the test set cannot match any template.

---

## 7. Residual limitations — stated plainly

### 7.1 Measured result: the mechanisms did not work

The §6.3 leakage test was run against the generated corpus. It failed.

| Corpus | Classifier accuracy | Majority baseline | Lift |
|---|---|---|---|
| Full chains, untruncated | **89.8%** | 17.4% | **+72.4 points** |
| After the truncation ladder | 54.6% | 17.2% | +37.4 points |

A bag of `event_type` 1–3 grams — no description text, no entities, nothing but the
sequence of event-type values — recovers the technique for nine blobs in ten. The four
mechanisms in §2–§5 reduced the leak but did not close it: three to four skeletons per
technique is not enough overlap to hide a distinctive event-type signature, and the
noise pool is drawn from a shared vocabulary that the classifier learns to ignore.
Note also that leakage is *worse* on untruncated chains, so a larger token budget makes
the problem larger, not smaller.

**This is accepted rather than fixed, and the reason is what the project claims.** The
deliverable is a model that turns structured telemetry into a well-formed, well-grounded,
human-readable incident report. Report quality, format adherence, and grounding are the
primary metrics (SCOPE.md §5.1), and none of them are affected by structural leakage — a
model cannot infer a good `## Summary`, a correct asset list, or a plausible root cause
from an event-type histogram. What leakage inflates is technique-ID accuracy, which
SCOPE.md §5.2 already classes as a secondary compliance signal reported against a
majority-class baseline. Closing the leak would mean sharing chain shapes across
techniques so the signal lived only in description text — a redesign that would improve
one secondary number while changing nothing about the primary claim. The honest move is
to publish the 89.8% figure alongside the technique-accuracy result, so no reader can
mistake that metric for a detection capability.

### 7.2 The broader residual limitation

The four mechanisms make the shortcut harder. They do not eliminate it, and no amount of
templating design can.

**The training data is synthetic telemetry derived from real incident classifications.**
Every event row, hostname, IP address, file path, and hash is fabricated by our
generator. The model is learning to map *our* synthetic telemetry grammar onto *our*
hand-curated technique labels. It is not learning from real SIEM output, and it has
never seen a real attack.

Three specific consequences that must be carried into the write-up rather than
discovered by a reader:

1. **Technique accuracy is a format-compliance signal, not a detection result.** It
   measures whether the model emits a well-formed, plausible technique ID consistent
   with the telemetry it was given. It does not measure whether the model could identify
   a technique in real telemetry, and it must never be reported as though it does.

2. **The ceiling is our curation.** Technique accuracy is agreement with
   `labels/technique_lookup.yaml`, which is 21 hand-written rows with three marked
   low-confidence. Systematic errors in that table are invisible to the metric.

3. **Grounding score measures internal consistency.** It detects entities the model
   invented that were not in the input — genuine hallucination detection, and worth
   having — but the entities it checks against are ones we invented too. It does not
   validate against the real world.

What this project can honestly claim: a small model can be fine-tuned to produce
well-structured, well-grounded, human-readable incident reports from structured
telemetry input, with high format adherence and low hallucination. That is the claim
SCOPE.md §5 is written to support. Technique and severity accuracy are secondary
compliance metrics reported alongside it, not the headline result.
