#!/usr/bin/env python3
"""
Run the base model, or base + LoRA adapter, over test.jsonl and save predictions.

Writes data/processed/preds_base.jsonl or preds_tuned.jsonl -- the two halves of
the comparison in SCOPE.md 5.3. The baseline must be produced with the same
prompt, the same decoding, and the same seed as the tuned model, or the
comparison measures the harness rather than the fine-tune.

Decoding is greedy (do_sample=False) so a re-run reproduces the file exactly.

    python -m src.generate_predictions --model base
    python -m src.generate_predictions --model tuned --adapter outputs/qlora-adapter
"""

import argparse
import json
import sys
import time
from pathlib import Path

from src.train_qlora import BASE_MODEL, MAX_SEQ_LEN, SEED

DEFAULT_TEST = Path("data/processed/test.jsonl")
OUT_DIR = Path("data/processed")

# Room for the longest reference report (432 tokens, DATASET_STATS.md 3) plus
# slack for a tuned model that has not yet learned to stop.
MAX_NEW_TOKENS = 700


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", choices=["base", "tuned"], required=True)
    ap.add_argument("--adapter", type=Path, default=Path("outputs/qlora-adapter"))
    ap.add_argument("--test", type=Path, default=DEFAULT_TEST)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--limit", type=int)
    ap.add_argument(
        "--load-4bit", action="store_true", help="quantize for inference; needed to fit a 16GB GPU"
    )
    args = ap.parse_args()

    if args.model == "tuned" and not args.adapter.exists():
        sys.exit(f"adapter not found at {args.adapter} -- train first")

    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    out_path = args.out or OUT_DIR / f"preds_{args.model}.jsonl"
    rows = load_jsonl(args.test)
    if args.limit:
        rows = rows[: args.limit]

    torch.manual_seed(SEED)
    has_cuda = torch.cuda.is_available()

    # The adapter dir carries its own tokenizer copy; prefer it so any special
    # tokens added at train time survive into inference.
    use_adapter_tok = args.model == "tuned" and (args.adapter / "tokenizer.json").exists()
    tok_src = args.adapter if use_adapter_tok else BASE_MODEL
    tokenizer = AutoTokenizer.from_pretrained(tok_src)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    kwargs = {"dtype": torch.bfloat16 if has_cuda else torch.float32}
    if args.load_4bit and has_cuda:
        from transformers import BitsAndBytesConfig

        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
            bnb_4bit_compute_dtype=torch.bfloat16,
        )
        kwargs["device_map"] = {"": 0}
    elif has_cuda:
        kwargs["device_map"] = {"": 0}

    print(f"loading {BASE_MODEL} ({args.model})")
    model = AutoModelForCausalLM.from_pretrained(BASE_MODEL, **kwargs)

    if args.model == "tuned":
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, str(args.adapter))
        print(f"attached adapter from {args.adapter}")

    model.eval()
    model.config.use_cache = True

    out_path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with out_path.open("w", encoding="utf-8") as fh:
        for i, row in enumerate(rows, 1):
            # Drop the reference assistant turn; keep system + user exactly as
            # the model saw them in training.
            prompt_messages = [m for m in row["messages"] if m["role"] != "assistant"]
            prompt = tokenizer.apply_chat_template(
                prompt_messages, tokenize=False, add_generation_prompt=True
            )
            inputs = tokenizer(prompt, return_tensors="pt", add_special_tokens=False)
            if has_cuda:
                inputs = {k: v.to(model.device) for k, v in inputs.items()}

            with torch.no_grad():
                out = model.generate(
                    **inputs,
                    max_new_tokens=MAX_NEW_TOKENS,
                    do_sample=False,  # greedy: reproducible
                    temperature=None,
                    top_p=None,
                    top_k=None,
                    pad_token_id=tokenizer.pad_token_id,
                )
            generated = out[0][inputs["input_ids"].shape[1] :]
            text = tokenizer.decode(generated, skip_special_tokens=True).strip()

            reference = next(m["content"] for m in row["messages"] if m["role"] == "assistant")
            fh.write(
                json.dumps(
                    {
                        "incident_id": row["incident_id"],
                        "attack_id": row["attack_id"],
                        "variant": args.model,
                        "prediction": text,
                        "reference": reference,
                        "n_prompt_tokens": int(inputs["input_ids"].shape[1]),
                        "n_generated_tokens": int(generated.shape[0]),
                    }
                )
                + "\n"
            )
            fh.flush()  # checkpoint: a killed session keeps what it produced
            print(
                f"[{i}/{len(rows)}] {row['incident_id'][:8]} {row['attack_id']:<10} "
                f"{generated.shape[0]} tokens"
            )

    print(f"\nwrote {out_path} ({len(rows)} predictions) in {time.time() - t0:.0f}s")
    print(f"max_seq_len {MAX_SEQ_LEN}, max_new_tokens {MAX_NEW_TOKENS}, greedy, seed {SEED}")


if __name__ == "__main__":
    main()
