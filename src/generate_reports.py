#!/usr/bin/env python3
"""
Generate reference incident reports for the selected telemetry blobs.

One blob in, one six-section Markdown report out, per the SCOPE.md section 3
output spec. These become the training targets, so correctness of *format* here
sets the ceiling for everything downstream -- a malformed reference teaches the
fine-tuned model to be malformed.

Uses the Google Gemini API. The key is read from .env as GEMINI_API_KEY and is
never logged, echoed, or written to any output file.

Design notes:
  * The ATT&CK technique is SUPPLIED from labels/technique_lookup.yaml, not
    guessed by the model. The model's job is to write the report, not to
    classify -- letting it pick would make the reference labels disagree with
    the lookup that scoring uses.
  * Every generation is validated against the SCOPE.md section 4 parsing rules
    before being accepted. Failures are recorded, never silently dropped.
  * Free-tier friendly: fixed inter-request throttle, exponential backoff with
    jitter on 429/5xx, and resume-from-checkpoint so a quota stop loses no work.

Usage:
    python -m src.generate_reports --limit 20      # pilot
    python -m src.generate_reports                 # everything not yet done
"""

import argparse
import json
import os
import random
import re
import sys
import time
from datetime import UTC, datetime

import yaml
from dotenv import load_dotenv

from src import config as c

BLOBS = c.PROCESSED / "blobs.jsonl"
SELECTED = c.PROCESSED / "selected.jsonl"
OUT = c.PROCESSED / "reports.jsonl"
FAILURES = c.PROCESSED / "report_failures.jsonl"
LOOKUP = c.ROOT / "labels" / "technique_lookup.yaml"

# Probed against the live API rather than assumed:
#   * the 2.5 family returns 404 ("no longer available") on this key -- do not
#     "fix" this back to gemini-2.5-flash
#   * gemini-3.5-flash works but its free tier caps at 20 requests, which cannot
#     cover a 400-record run
#   * gemini-3.5-flash-lite rejects thinking_budget=0 with a 400
# gemini-3.1-flash-lite accepts the config and has free-tier headroom.
MODEL = "gemini-3.1-flash-lite"

# Free-tier pacing. Conservative on purpose -- a sustained 429 storm costs more
# wall-clock than simply going slower.
MIN_INTERVAL_S = 6.0
MAX_ATTEMPTS = 5
BACKOFF_BASE_S = 8.0
BACKOFF_CAP_S = 240.0
CHECKPOINT_EVERY = 5

# The SCOPE.md 3.7 reference report is 451 Qwen tokens; 2000 Gemini output tokens
# leaves ample room without inviting a rambling report.
MAX_OUTPUT_TOKENS = 3000

SYSTEM_PROMPT = """\
You are a senior security analyst writing an incident report from raw SIEM telemetry.

OUTPUT FORMAT -- follow exactly, no deviation:

Emit Markdown with exactly these six headings, in this order, spelled exactly:

## Summary
## Affected Assets
## Attack Technique
## Severity
## Root Cause
## Recommended Actions

No preamble before `## Summary`. No text after the last recommended action. No
other headings. No code fences around the report.

SECTION RULES

## Summary
2-4 sentences, 40-90 words, plain prose, no bullets. Say what happened, in what
order, and what the outcome was. Name at least one asset. Do not speculate about
who the attacker was or name any threat group.

## Affected Assets
One bullet per asset genuinely involved, formatted exactly:
- <hostname> (<role>) — <what happened to it>
1-6 bullets, each 20 words or fewer. Use only hostnames from the ASSETS block.
Omit assets that appear in the blob but are not involved in the incident.

## Attack Technique
First line, exactly: <TECHNIQUE_ID> — <TECHNIQUE_NAME>
using the ID and name given to you in the prompt. Do not choose a different
technique and do not mention any other ATT&CK ID anywhere in this section.
Then one sentence, 30 words or fewer, justifying the mapping by pointing at a
specific numbered event.

## Severity
One line, exactly: <Label> — <rationale, 25 words or fewer>
<Label> must be exactly one of: Low, Medium, High, Critical.
  Low      attempt blocked or failed; nothing compromised; no data accessed
  Medium   one non-critical asset compromised; no sensitive data; no lateral movement
  High     lateral movement, or a high-criticality asset compromised, or sensitive
           data accessed without confirmed egress
  Critical confirmed egress of sensitive data, or a critical-criticality asset
           compromised, or org-wide loss of availability

## Root Cause
1-3 sentences, 25-60 words. State the CONTROL FAILURE that made this possible --
not a restatement of the attack chain. It must be traceable to something in the
telemetry: an event, an account privilege, or the analyst_notes line. If the
telemetry genuinely does not support one, write exactly:
Insufficient evidence in the available telemetry to determine root cause.

## Recommended Actions
A numbered list, 3-6 items, each starting with an imperative verb and 25 words or
fewer. Order them most urgent first: containment, then eradication, then
hardening. Defensive actions only -- no offensive measures, no vendor product names.

OUTPUT ONLY THE REPORT. Do not restate these requirements, do not plan or explain
your approach, do not add commentary before or after. The very first characters of
your response must be `## Summary`.

GROUNDING -- the hard rule:

Every hostname, IP address, account name, file path, and hash that appears in your
report MUST appear verbatim in the telemetry blob. Invent nothing. If you need a
detail the telemetry does not contain, leave it out and write around it. Do not
add plausible-sounding specifics. Do not round, reformat, or "correct" any
identifier you copy. This is checked automatically and a report containing an
entity absent from its input is discarded.
"""

USER_TEMPLATE = """\
Write the incident report for the telemetry below.

The MITRE ATT&CK technique for this incident has already been determined. Use it
verbatim in the `## Attack Technique` section:

  TECHNIQUE_ID: {attack_id}
  TECHNIQUE_NAME: {attack_name}

TELEMETRY:

{blob}
"""

# SCOPE.md section 4 parsing rules, applied to the generation before acceptance.
SECTION_RE = {
    "summary": re.compile(r"^##[ ]+Summary\s*\n(.*?)(?=^##[ ]+|\Z)", re.S | re.M),
    "assets": re.compile(r"^##[ ]+Affected[ ]Assets\s*\n(.*?)(?=^##[ ]+|\Z)", re.S | re.M),
    "technique": re.compile(r"^##[ ]+Attack[ ]Technique\s*\n(.*?)(?=^##[ ]+|\Z)", re.S | re.M),
    "severity": re.compile(r"^##[ ]+Severity\s*\n(.*?)(?=^##[ ]+|\Z)", re.S | re.M),
    "root_cause": re.compile(r"^##[ ]+Root[ ]Cause\s*\n(.*?)(?=^##[ ]+|\Z)", re.S | re.M),
    "actions": re.compile(r"^##[ ]+Recommended[ ]Actions\s*\n(.*?)(?=^##[ ]+|\Z)", re.S | re.M),
}
TECH_ID_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")
SEVERITY_RE = re.compile(r"^\s*(Low|Medium|High|Critical)\b", re.I)

# Entity patterns for the grounding check (SCOPE.md section 4.6).
ENTITY_RE = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "hostname": re.compile(r"\b[A-Z]{2,4}-[A-Z]{2,3}\d{2}\b"),
    "account": re.compile(r"\b[A-Z]+\\[a-zA-Z0-9._\-]+\b"),
    # Trailing sentence punctuation must not be captured, or a correctly copied
    # path at the end of a sentence reads as an invented entity.
    "path": re.compile(r"\b[A-Za-z]:\\[^\s,;\"'|]*[^\s,;\"'|.)\]]"),
    "hash": re.compile(r"\b[a-f0-9]{12,64}\b"),
}


def parse_report(text):
    """Return (sections, problems). Mirrors what the eval harness will do."""
    sections, problems = {}, []
    for name, pat in SECTION_RE.items():
        m = pat.search(text)
        if not m:
            problems.append(f"missing section: {name}")
        else:
            sections[name] = m.group(1).strip()
    return sections, problems


def validate(text, blob, attack_id):
    """Structural + grounding checks. Returns a list of problems (empty == good)."""
    sections, problems = parse_report(text)

    if text.lstrip().startswith("```"):
        problems.append("wrapped in a code fence")

    tech = sections.get("technique", "")
    ids = {f"T{a}" + (f".{b}" if b else "") for a, b in TECH_ID_RE.findall(tech)}
    if not ids:
        problems.append("no ATT&CK ID in Attack Technique")
    elif ids != {attack_id}:
        problems.append(f"technique mismatch: found {sorted(ids)}, expected {attack_id}")

    sev = sections.get("severity", "")
    m = SEVERITY_RE.match(sev)
    if not m:
        problems.append(f"severity not one of the four labels: {sev.splitlines()[:1]}")
    elif m.group(1).title() not in c.SEVERITY_LEVELS:
        problems.append(f"bad severity label: {m.group(1)}")

    # Grounding: every entity in the report must be verbatim in the blob.
    ungrounded = []
    for kind, pat in ENTITY_RE.items():
        in_blob = set(pat.findall(blob))
        for ent in set(pat.findall(text)):
            if ent not in in_blob:
                ungrounded.append(f"{kind}:{ent}")
    if ungrounded:
        problems.append("ungrounded entities: " + ", ".join(sorted(ungrounded)[:6]))

    return problems


def load_done():
    """incident_ids already generated, so a resumed run does no duplicate work."""
    if not OUT.exists():
        return set()
    done = set()
    for line in OUT.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                done.add(json.loads(line)["incident_id"])
            except (json.JSONDecodeError, KeyError):
                continue
    return done


def log_failure(incident_id, reason, detail=""):
    FAILURES.parent.mkdir(parents=True, exist_ok=True)
    with FAILURES.open("a", encoding="utf-8") as fh:
        fh.write(
            json.dumps(
                {
                    "incident_id": incident_id,
                    "reason": reason,
                    "detail": detail[:500],
                    "at": datetime.now(UTC).isoformat(),
                }
            )
            + "\n"
        )


RETRY_DELAY_RE = re.compile(r"retry in ([\d.]+)s", re.I)


def retry_delay_from(exc):
    """Seconds the API asked us to wait, if it said so. None otherwise."""
    m = RETRY_DELAY_RE.search(str(exc))
    if not m:
        return None
    try:
        return min(float(m.group(1)) + 1.0, BACKOFF_CAP_S)
    except ValueError:
        return None


def generate_one(client, blob, attack_id, attack_name):
    """One report, with backoff. Returns (text, attempts) or raises."""
    from google.genai import errors as genai_errors

    last = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = client.models.generate_content(
                model=MODEL,
                contents=USER_TEMPLATE.format(
                    attack_id=attack_id, attack_name=attack_name, blob=blob
                ),
                config={
                    "system_instruction": SYSTEM_PROMPT,
                    "temperature": 0.3,
                    "max_output_tokens": MAX_OUTPUT_TOKENS,
                    # Thinking is on by default on this model and is NOT capped by
                    # a small budget -- a budget of 512 still spent 1,839 thought
                    # tokens, starving the response and truncating it at
                    # MAX_TOKENS. Disable it: this is a formatting task with the
                    # technique already supplied, so there is nothing to reason out.
                    "thinking_config": {"thinking_budget": 0},
                },
            )
            text = (resp.text or "").strip()
            if not text:
                raise RuntimeError("empty response")
            return text, attempt
        except genai_errors.ClientError as e:
            last = e
            if getattr(e, "code", None) != 429:
                raise  # 400/404 are our bug, not transient -- fail fast
        except (genai_errors.ServerError, RuntimeError) as e:
            last = e

        if attempt < MAX_ATTEMPTS:
            # A 429 body carries the exact wait ("Please retry in 31.02s"). Honour
            # it -- blind exponential backoff either wastes time or retries too
            # early and burns another request against the quota.
            server_delay = retry_delay_from(last)
            delay = (
                server_delay
                if server_delay
                else min(BACKOFF_BASE_S * 2 ** (attempt - 1), BACKOFF_CAP_S)
            )
            delay += random.uniform(0, delay * 0.25)  # jitter, avoid lockstep retries
            print(
                f"    retry {attempt}/{MAX_ATTEMPTS - 1} in {delay:.0f}s ({type(last).__name__})",
                file=sys.stderr,
            )
            time.sleep(delay)
    raise last


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, help="stop after this many new reports")
    ap.add_argument("--split", choices=["train", "test"], help="restrict to one split")
    args = ap.parse_args()

    load_dotenv(c.ROOT / ".env")
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        sys.exit("GEMINI_API_KEY is not set. Put it in .env (see .env.example).")

    from google import genai

    client = genai.Client(api_key=key)

    lut = yaml.safe_load(LOOKUP.read_text(encoding="utf-8"))
    names = {r["attack_id"]: r["attack_name"] for r in lut["techniques"]}

    meta = {}
    for line in SELECTED.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        meta[row["incident_id"]] = row

    blobs = [json.loads(x) for x in BLOBS.read_text(encoding="utf-8").splitlines()]
    blobs = [b for b in blobs if b["blob"]]
    if args.split:
        blobs = [b for b in blobs if b.get("split") == args.split]

    done = load_done()
    todo = [b for b in blobs if b["incident_id"] not in done]
    if args.limit:
        # blobs.jsonl is grouped by technique, so a head slice would make a pilot
        # of one class. Round-robin across techniques instead.
        by_tech = {}
        for b in todo:
            by_tech.setdefault(meta[b["incident_id"]]["attack_id"], []).append(b)
        interleaved, idx = [], 0
        while len(interleaved) < len(todo):
            added = False
            for t in sorted(by_tech):
                if idx < len(by_tech[t]):
                    interleaved.append(by_tech[t][idx])
                    added = True
            if not added:
                break
            idx += 1
        todo = interleaved[: args.limit]

    print(f"model     : {MODEL}")
    print(f"blobs     : {len(blobs)} total, {len(done)} already generated")
    print(f"this run  : {len(todo)}")
    print(f"throttle  : {MIN_INTERVAL_S}s between requests\n")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    buffer, ok, bad, failed = [], 0, 0, 0
    last_call = 0.0

    def flush():
        if not buffer:
            return
        with OUT.open("a", encoding="utf-8") as fh:
            for row in buffer:
                fh.write(json.dumps(row) + "\n")
        buffer.clear()

    for i, b in enumerate(todo, 1):
        iid = b["incident_id"]
        aid = meta[iid]["attack_id"]

        wait = MIN_INTERVAL_S - (time.time() - last_call)
        if wait > 0:
            time.sleep(wait)
        last_call = time.time()

        try:
            text, attempts = generate_one(client, b["blob"], aid, names[aid])
        except Exception as e:  # noqa: BLE001 - log and continue; never skip silently
            failed += 1
            log_failure(iid, type(e).__name__, str(e))
            print(f"[{i}/{len(todo)}] {iid[:8]} FAILED {type(e).__name__}", file=sys.stderr)
            continue

        problems = validate(text, b["blob"], aid)
        if problems:
            bad += 1
            log_failure(iid, "validation", "; ".join(problems))
        else:
            ok += 1

        buffer.append(
            {
                "incident_id": iid,
                "split": b["split"],
                "attack_id": aid,
                "attack_name": names[aid],
                "skeleton": b["skeleton"],
                "report": text,
                "valid": not problems,
                "problems": problems,
                "attempts": attempts,
                "model": MODEL,
            }
        )
        flag = "ok " if not problems else "BAD"
        print(f"[{i}/{len(todo)}] {iid[:8]} {aid:<10} {flag} {problems[:1]}")

        if len(buffer) >= CHECKPOINT_EVERY:
            flush()

    flush()
    print(f"\ngenerated {ok + bad}: {ok} valid, {bad} with problems, {failed} failed")
    print(f"wrote {OUT}")
    if bad or failed:
        print(f"details in {FAILURES}")


if __name__ == "__main__":
    main()
