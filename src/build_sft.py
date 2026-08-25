#!/usr/bin/env python3
"""
Write data/processed/train.jsonl and test.jsonl in Qwen2.5 chat format for SFT.

Each line is {"messages": [system, user, assistant]}:
  system    -- the format contract, identical to the one used at generation time
  user      -- the telemetry blob
  assistant -- the reference report

Every example is measured with the real Qwen2.5 tokenizer after applying the
model's own chat template. Anything that would not fit MAX_SEQ_LEN is dropped
and reported rather than silently truncated -- a truncated training example
teaches the model to stop mid-report.
"""

import json
import statistics
import sys
from collections import Counter

from src import config as c

REPORTS = c.PROCESSED / "reports.jsonl"
BLOBS = c.PROCESSED / "blobs.jsonl"
TRAIN = c.PROCESSED / "train.jsonl"
TEST = c.PROCESSED / "test.jsonl"

# Training-time system prompt. Deliberately terser than the generation-time one
# in generate_reports.py: at inference the fine-tuned model has learned the
# format, so paying ~400 tokens per example to restate it wastes budget the blob
# needs. It still names the six headings and the four severity labels, because
# those are the contract the eval harness parses.
SYSTEM = (
    "You are a security incident analyst. Given a raw telemetry blob, write an "
    "incident report in Markdown with exactly these six headings, in this order: "
    "## Summary, ## Affected Assets, ## Attack Technique, ## Severity, ## Root Cause, "
    "## Recommended Actions. Severity must be exactly one of Low, Medium, High, "
    "Critical. Attack Technique must be a MITRE ATT&CK ID and canonical name. "
    "Use only entities that appear in the telemetry; never invent hostnames, IP "
    "addresses, accounts, file paths, or hashes."
)


def main():
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(c.BASE_MODEL)

    reports = [json.loads(x) for x in REPORTS.read_text(encoding="utf-8").splitlines() if x.strip()]
    blobs = {
        b["incident_id"]: b
        for b in (json.loads(x) for x in BLOBS.read_text(encoding="utf-8").splitlines())
    }

    kept = {"train": [], "test": []}
    dropped = []
    lengths = []

    for r in reports:
        blob = blobs[r["incident_id"]]["blob"]
        messages = [
            {"role": "system", "content": SYSTEM},
            {"role": "user", "content": blob},
            {"role": "assistant", "content": r["report"]},
        ]

        # Measure the full rendered sequence the trainer will actually see,
        # including the chat template's own tokens.
        rendered = tok.apply_chat_template(messages, tokenize=False)
        n_tokens = len(tok.encode(rendered))
        lengths.append(n_tokens)

        row = {
            "messages": messages,
            "incident_id": r["incident_id"],
            "attack_id": r["attack_id"],
            "n_tokens": n_tokens,
        }
        if n_tokens > c.MAX_SEQ_LEN:
            dropped.append((r["incident_id"], r["attack_id"], r["split"], n_tokens))
            continue
        kept[r["split"]].append(row)

    for path, split in ((TRAIN, "train"), (TEST, "test")):
        with path.open("w", encoding="utf-8") as fh:
            for row in kept[split]:
                fh.write(json.dumps(row) + "\n")

    lengths.sort()
    print(f"tokenizer     : {c.BASE_MODEL}")
    print(f"max_seq_len   : {c.MAX_SEQ_LEN}")
    print(
        f"examples      : {len(reports)} in, {len(kept['train'])} train + "
        f"{len(kept['test'])} test written, {len(dropped)} dropped"
    )
    print(
        f"full sequence : median {statistics.median(lengths):.0f}  "
        f"p90 {lengths[int(0.9 * len(lengths))]}  max {lengths[-1]}"
    )
    print(f"headroom      : {c.MAX_SEQ_LEN - lengths[-1]} tokens under the cap at worst")

    if dropped:
        print(f"\nDROPPED {len(dropped)} example(s) over {c.MAX_SEQ_LEN}:")
        for iid, aid, split, n in dropped:
            print(f"  {iid[:8]} {aid:<10} {split:<5} {n} tokens")
        print("\nper-class effect of the drops:")
        for aid, cnt in Counter(d[1] for d in dropped).most_common():
            print(f"  {aid}: -{cnt}")

    print(f"\nwrote {TRAIN}")
    print(f"wrote {TEST}")

    for split in ("train", "test"):
        dist = Counter(r["attack_id"] for r in kept[split])
        missing = [t for t in {r["attack_id"] for r in reports} if t not in dist]
        print(
            f"{split:<5} classes: {len(dist)}"
            + (f"  MISSING {missing}" if missing else "  (all present)")
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
