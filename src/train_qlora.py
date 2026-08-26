#!/usr/bin/env python3
"""
QLoRA supervised fine-tune of Qwen2.5-3B-Instruct on the incident-report corpus.

Every hyperparameter is a constant in the HYPERPARAMETERS block below. Nothing
that affects the run is buried in a function.

The one subtle piece is loss masking. A chat example contains the system prompt,
the telemetry blob, and the report; only the report should contribute to the
loss. Training on the blob would teach the model to generate telemetry, which is
not the task and wastes most of the sequence. `mask_prompt_tokens` sets labels to
-100 for everything up to and including the assistant header, so gradient flows
only through the report and its end-of-turn token. `python -m src.train_qlora
--smoke` prints a token-by-token view of exactly what is masked.

Runs on a 16GB T4 or P100 (Kaggle). See notebooks/train_kaggle.ipynb.
"""

import argparse
import json
import math
import os
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path

# ===========================================================================
# HYPERPARAMETERS
# ===========================================================================

BASE_MODEL = "Qwen/Qwen2.5-3B-Instruct"
MAX_SEQ_LEN = 1536

# --- quantization (SCOPE.md section 6: 4-bit QLoRA) ------------------------
LOAD_IN_4BIT = True
BNB_QUANT_TYPE = "nf4"
BNB_DOUBLE_QUANT = True
BNB_COMPUTE_DTYPE = "bfloat16"  # falls back to float16 on T4, which lacks bf16

# --- LoRA ------------------------------------------------------------------
LORA_R = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.05
LORA_BIAS = "none"
# Attention *and* MLP projections. Attention-only adapters underperform on
# format-following tasks like this one, and the MLP projections are where most
# of the "what does a report look like" capacity sits.
LORA_TARGET_MODULES = [
    "q_proj",
    "k_proj",
    "v_proj",
    "o_proj",  # attention
    "gate_proj",
    "up_proj",
    "down_proj",  # MLP
]

# --- optimisation ----------------------------------------------------------
EPOCHS = 3
LEARNING_RATE = 2e-4  # standard for LoRA; 10-20x what full FT would use
LR_SCHEDULER = "cosine"
WARMUP_RATIO = 0.03
WEIGHT_DECAY = 0.01
MAX_GRAD_NORM = 0.3
OPTIMIZER = "paged_adamw_8bit"  # paged: survives the optimiser-state spike on 16GB

# Sized for 16GB at 1536 tokens with 4-bit weights and gradient checkpointing.
# Effective batch = 1 * 8 = 8. Raise PER_DEVICE_BATCH to 2 only on >=24GB.
PER_DEVICE_BATCH = 1
GRAD_ACCUM_STEPS = 8
GRADIENT_CHECKPOINTING = True

# --- data ------------------------------------------------------------------
# Held out from train.jsonl for per-epoch eval loss. The 40-record test.jsonl is
# NOT touched here -- it is reserved for the final comparison in SCOPE.md 5.3.
EVAL_FRACTION = 0.10
SEED = 20260826

# --- logging / checkpointing ----------------------------------------------
LOGGING_STEPS = 5
SAVE_STRATEGY = "epoch"
EVAL_STRATEGY = "epoch"
SAVE_TOTAL_LIMIT = 3  # Kaggle sessions die; keep every epoch's adapter

# ===========================================================================

DEFAULT_TRAIN = Path("data/processed/train.jsonl")
DEFAULT_OUT = Path("outputs/qlora-adapter")


@dataclass
class RunConfig:
    """Everything that defines the run, serialised next to the adapter."""

    base_model: str = BASE_MODEL
    max_seq_len: int = MAX_SEQ_LEN
    load_in_4bit: bool = LOAD_IN_4BIT
    bnb_quant_type: str = BNB_QUANT_TYPE
    bnb_double_quant: bool = BNB_DOUBLE_QUANT
    bnb_compute_dtype: str = BNB_COMPUTE_DTYPE
    lora_r: int = LORA_R
    lora_alpha: int = LORA_ALPHA
    lora_dropout: float = LORA_DROPOUT
    lora_target_modules: tuple = tuple(LORA_TARGET_MODULES)
    epochs: int = EPOCHS
    learning_rate: float = LEARNING_RATE
    lr_scheduler: str = LR_SCHEDULER
    warmup_ratio: float = WARMUP_RATIO
    weight_decay: float = WEIGHT_DECAY
    max_grad_norm: float = MAX_GRAD_NORM
    optimizer: str = OPTIMIZER
    per_device_batch: int = PER_DEVICE_BATCH
    grad_accum_steps: int = GRAD_ACCUM_STEPS
    gradient_checkpointing: bool = GRADIENT_CHECKPOINTING
    eval_fraction: float = EVAL_FRACTION
    seed: int = SEED


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


def load_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def find_assistant_start(tokenizer, messages):
    """Token index where the assistant's reply begins.

    Rendering the conversation without the final assistant turn gives exactly the
    prompt prefix; its token length is the boundary. This avoids searching for a
    literal marker string, which breaks whenever a chat template changes.
    """
    prompt_only = tokenizer.apply_chat_template(
        messages[:-1], tokenize=False, add_generation_prompt=True
    )
    return len(tokenizer(prompt_only, add_special_tokens=False)["input_ids"])


def encode_example(tokenizer, messages, max_len=MAX_SEQ_LEN):
    """Tokenize one chat example and mask everything before the report."""
    full = tokenizer.apply_chat_template(messages, tokenize=False)
    ids = tokenizer(full, add_special_tokens=False)["input_ids"][:max_len]
    boundary = min(find_assistant_start(tokenizer, messages), len(ids))

    labels = list(ids)
    for i in range(boundary):
        labels[i] = -100  # system + user turns: predicted, never learned from

    return {
        "input_ids": ids,
        "attention_mask": [1] * len(ids),
        "labels": labels,
        "boundary": boundary,
    }


class Collator:
    """Right-pads a batch; pad positions are masked out of the loss."""

    def __init__(self, pad_id):
        self.pad_id = pad_id

    def __call__(self, features):
        import torch

        width = max(len(f["input_ids"]) for f in features)
        batch = {"input_ids": [], "attention_mask": [], "labels": []}
        for f in features:
            gap = width - len(f["input_ids"])
            batch["input_ids"].append(f["input_ids"] + [self.pad_id] * gap)
            batch["attention_mask"].append(f["attention_mask"] + [0] * gap)
            batch["labels"].append(f["labels"] + [-100] * gap)
        return {k: torch.tensor(v, dtype=torch.long) for k, v in batch.items()}


class ListDataset:
    def __init__(self, rows):
        self.rows = rows

    def __len__(self):
        return len(self.rows)

    def __getitem__(self, i):
        r = self.rows[i]
        return {k: r[k] for k in ("input_ids", "attention_mask", "labels")}


# ---------------------------------------------------------------------------
# Masking check
# ---------------------------------------------------------------------------


def show_masking(tokenizer, example, max_show=28):
    """Print which tokens are masked and which carry loss."""
    ids, labels = example["input_ids"], example["labels"]
    n_masked = sum(1 for x in labels if x == -100)
    n_train = len(labels) - n_masked

    print(f"  sequence length : {len(ids)}")
    print(f"  masked (-100)   : {n_masked}  <- system + telemetry blob")
    print(f"  trained on      : {n_train}  <- the report")
    print(f"  boundary index  : {example['boundary']}")
    print()
    print(f"  last {max_show // 2} MASKED tokens (end of the blob / assistant header):")
    lo = max(0, example["boundary"] - max_show // 2)
    print("    " + repr("".join(tokenizer.decode([t]) for t in ids[lo : example["boundary"]])))
    print()
    print(f"  first {max_show} TRAINED tokens (start of the report):")
    hi = min(len(ids), example["boundary"] + max_show)
    print("    " + repr("".join(tokenizer.decode([t]) for t in ids[example["boundary"] : hi])))
    print()

    decoded_train = tokenizer.decode([t for t, m in zip(ids, labels, strict=True) if m != -100])
    ok = decoded_train.lstrip().startswith("## Summary")
    print(f"  trained region starts with '## Summary': {ok}")
    if not ok:
        print(f"    !! it starts with: {decoded_train[:80]!r}")
    blob_leaked = "=== TELEMETRY BLOB ===" in decoded_train
    print(f"  telemetry blob absent from trained region: {not blob_leaked}")
    return ok and not blob_leaked


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------


# Smoke-test stand-in. A randomly-initialised Qwen2 of a few million parameters,
# built from config so NOTHING is downloaded. It keeps the real architecture, so
# the LoRA target modules below resolve exactly as they will on the 3B, and it
# uses the real Qwen tokenizer (a few MB, already needed for the dataset build).
# Real weights and real training happen on Kaggle, never locally.
SMOKE_HIDDEN = 128
SMOKE_LAYERS = 2
SMOKE_HEADS = 4
SMOKE_KV_HEADS = 2
SMOKE_INTERMEDIATE = 256


def build_smoke_model(tokenizer):
    """Tiny randomly-initialised Qwen2. No download, no real weights."""
    import torch
    from transformers import AutoModelForCausalLM, Qwen2Config

    config = Qwen2Config(
        vocab_size=len(tokenizer),
        hidden_size=SMOKE_HIDDEN,
        num_hidden_layers=SMOKE_LAYERS,
        num_attention_heads=SMOKE_HEADS,
        num_key_value_heads=SMOKE_KV_HEADS,
        intermediate_size=SMOKE_INTERMEDIATE,
        max_position_embeddings=MAX_SEQ_LEN,
        tie_word_embeddings=True,
    )
    model = AutoModelForCausalLM.from_config(config)
    model = model.to(torch.float32)
    n = sum(p.numel() for p in model.parameters())
    print(
        f"smoke stand-in: randomly-initialised Qwen2, {n / 1e6:.1f}M params, "
        f"{SMOKE_LAYERS} layers (no weights downloaded)"
    )
    model.config.use_cache = False
    return model


def build_model(cfg):
    import torch
    from transformers import AutoModelForCausalLM

    has_cuda = torch.cuda.is_available()
    bf16_ok = has_cuda and torch.cuda.is_bf16_supported()
    compute_dtype = torch.bfloat16 if bf16_ok else torch.float16

    kwargs = {"dtype": compute_dtype if has_cuda else torch.float32}

    if cfg.load_in_4bit and has_cuda:
        from transformers import BitsAndBytesConfig

        kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type=cfg.bnb_quant_type,
            bnb_4bit_use_double_quant=cfg.bnb_double_quant,
            bnb_4bit_compute_dtype=compute_dtype,
        )
        kwargs["device_map"] = {"": 0}
    elif not has_cuda:
        sys.exit(
            "Refusing to load the 3B base model without a GPU.\n"
            "Real weights and training belong on Kaggle (notebooks/train_kaggle.ipynb).\n"
            "To verify this script locally, use --smoke, which builds a tiny "
            "randomly-initialised stand-in and downloads nothing."
        )

    model = AutoModelForCausalLM.from_pretrained(cfg.base_model, **kwargs)
    model.config.use_cache = False  # incompatible with gradient checkpointing
    return model


def attach_lora(model, cfg, quantized):
    from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training

    if quantized:
        model = prepare_model_for_kbit_training(
            model, use_gradient_checkpointing=cfg.gradient_checkpointing
        )
    peft_cfg = LoraConfig(
        r=cfg.lora_r,
        lora_alpha=cfg.lora_alpha,
        lora_dropout=cfg.lora_dropout,
        bias=LORA_BIAS,
        task_type="CAUSAL_LM",
        target_modules=list(cfg.lora_target_modules),
    )
    model = get_peft_model(model, peft_cfg)
    model.print_trainable_parameters()
    return model


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", type=Path, default=DEFAULT_TRAIN)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument(
        "--smoke",
        action="store_true",
        help="8 examples, 2 steps, no quantization -- proves the "
        "pipeline runs and the loss masking is correct",
    )
    ap.add_argument("--smoke-n", type=int, default=8)
    ap.add_argument("--smoke-steps", type=int, default=2)
    args = ap.parse_args()

    import numpy as np
    import torch
    from transformers import AutoTokenizer, Trainer, TrainingArguments

    cfg = RunConfig()
    random.seed(cfg.seed)
    np.random.seed(cfg.seed)
    torch.manual_seed(cfg.seed)

    tokenizer = AutoTokenizer.from_pretrained(cfg.base_model)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    rows = load_jsonl(args.train)
    if args.smoke:
        rows = rows[: args.smoke_n]
    print(f"loaded {len(rows)} examples from {args.train}")

    encoded = [encode_example(tokenizer, r["messages"], cfg.max_seq_len) for r in rows]

    print("\n=== loss masking check ===")
    masking_ok = show_masking(tokenizer, encoded[0])
    if not masking_ok:
        sys.exit("loss masking is wrong -- refusing to train")

    over = [e for e in encoded if len(e["input_ids"]) >= cfg.max_seq_len]
    if over:
        print(
            f"WARNING: {len(over)} example(s) hit the {cfg.max_seq_len} cap and were truncated",
            file=sys.stderr,
        )

    rng = random.Random(cfg.seed)
    order = list(range(len(encoded)))
    rng.shuffle(order)
    n_eval = max(1, int(len(order) * cfg.eval_fraction)) if len(order) > 1 else 0
    eval_rows = [encoded[i] for i in order[:n_eval]]
    train_rows = [encoded[i] for i in order[n_eval:]]
    print(
        f"\ntrain {len(train_rows)} / eval {len(eval_rows)} "
        f"(eval held out of train.jsonl; test.jsonl untouched)"
    )

    has_cuda = torch.cuda.is_available()
    quantized = cfg.load_in_4bit and has_cuda and not args.smoke

    model = build_smoke_model(tokenizer) if args.smoke else build_model(cfg)
    model = attach_lora(model, cfg, quantized)

    # transformers 5 removed `warmup_ratio` (warmup_steps remains). Compute the
    # step count here so this runs on both v4 and v5 -- the Kaggle image version
    # is not under our control.
    n_epochs = 1 if args.smoke else cfg.epochs
    accum = 1 if args.smoke else cfg.grad_accum_steps
    steps_per_epoch = max(1, math.ceil(len(train_rows) / (cfg.per_device_batch * accum)))
    total_steps = args.smoke_steps if args.smoke else steps_per_epoch * n_epochs
    warmup_steps = max(1, round(total_steps * cfg.warmup_ratio))
    print(
        f"schedule: {total_steps} total steps, {warmup_steps} warmup "
        f"({cfg.warmup_ratio:.0%}), {cfg.lr_scheduler}"
    )

    args.out.mkdir(parents=True, exist_ok=True)
    targs = TrainingArguments(
        output_dir=str(args.out),
        num_train_epochs=1 if args.smoke else cfg.epochs,
        max_steps=args.smoke_steps if args.smoke else -1,
        per_device_train_batch_size=cfg.per_device_batch,
        per_device_eval_batch_size=cfg.per_device_batch,
        gradient_accumulation_steps=1 if args.smoke else cfg.grad_accum_steps,
        gradient_checkpointing=cfg.gradient_checkpointing and has_cuda,
        learning_rate=cfg.learning_rate,
        lr_scheduler_type=cfg.lr_scheduler,
        warmup_steps=warmup_steps,
        weight_decay=cfg.weight_decay,
        max_grad_norm=cfg.max_grad_norm,
        optim=cfg.optimizer if quantized else "adamw_torch",
        bf16=has_cuda and torch.cuda.is_bf16_supported(),
        fp16=has_cuda and not torch.cuda.is_bf16_supported(),
        logging_steps=1 if args.smoke else LOGGING_STEPS,
        eval_strategy="no" if (args.smoke or not eval_rows) else EVAL_STRATEGY,
        save_strategy="no" if args.smoke else SAVE_STRATEGY,
        save_total_limit=SAVE_TOTAL_LIMIT,
        seed=cfg.seed,
        report_to=[],
        remove_unused_columns=False,
    )

    trainer = Trainer(
        model=model,
        args=targs,
        train_dataset=ListDataset(train_rows),
        eval_dataset=ListDataset(eval_rows) if eval_rows and not args.smoke else None,
        data_collator=Collator(tokenizer.pad_token_id),
    )

    print("\n=== training ===")
    t0 = time.time()
    result = trainer.train()
    elapsed = time.time() - t0

    history = [h for h in trainer.state.log_history if "loss" in h or "eval_loss" in h]
    final_train = next((h["loss"] for h in reversed(history) if "loss" in h), None)
    final_eval = next((h["eval_loss"] for h in reversed(history) if "eval_loss" in h), None)

    print(f"\ntrained {result.global_step} steps in {elapsed:.1f}s")
    print(f"final train loss: {final_train}")
    if final_eval is not None:
        print(f"final eval loss : {final_eval}  (ppl {math.exp(final_eval):.2f})")

    if args.smoke:
        print("\nSMOKE TEST PASSED -- pipeline runs, masking verified. Nothing saved.")
        return

    model.save_pretrained(args.out)
    tokenizer.save_pretrained(args.out)
    summary = {
        "config": asdict(cfg),
        "n_train": len(train_rows),
        "n_eval": len(eval_rows),
        "steps": result.global_step,
        "elapsed_seconds": round(elapsed, 1),
        "final_train_loss": final_train,
        "final_eval_loss": final_eval,
        "log_history": history,
        "quantized": quantized,
        "gpu": torch.cuda.get_device_name(0) if has_cuda else None,
    }
    (args.out / "training_summary.json").write_text(json.dumps(summary, indent=2))
    print(f"\nsaved adapter, tokenizer, and training_summary.json to {args.out}")


if __name__ == "__main__":
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    main()
