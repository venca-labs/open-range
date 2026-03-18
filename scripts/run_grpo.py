#!/usr/bin/env python3
"""Standalone GRPO training script for remote GPU instances.

Runs Unsloth GRPO with progressive + binary reward functions on
Qwen3.5-4B (from SFT checkpoint). Self-contained -- no open-range imports needed.

Usage:
    python3 run_grpo.py
    python3 run_grpo.py --model /workspace/outputs/sft-merged
    python3 run_grpo.py --reward binary
"""

import argparse
import difflib
import json
import logging
import math
import os
import random
import re
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("grpo")

os.environ.setdefault("PYTORCH_CUDA_ALLOC_CONF", "expandable_segments:True")

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MODEL = "/workspace/outputs/sft-merged"  # SFT checkpoint
DATA = "/workspace/data/grpo_combined.jsonl"
OUTPUT = "/workspace/outputs/grpo"
SEQ = 4096
COMP_LEN = 2048
NUM_GEN = 4
BATCH = 1
GRAD_ACCUM = 2
LR = 5e-6
BETA = 0.04
TEMP = 0.7
LORA_R = 16
LORA_ALPHA = 16
EPOCHS = 1

# ---------------------------------------------------------------------------
# Tool call parsing
# ---------------------------------------------------------------------------

_TOOL_CALL_RE = re.compile(
    r"<tool_call>\s*<function=(\w+)>(.*?)</function>\s*</tool_call>",
    re.DOTALL,
)
_PARAM_RE = re.compile(r"<parameter=(\w+)>(.*?)</parameter>", re.DOTALL)
_FLAG_RE = re.compile(r"flag\{[^}]+\}", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Known tools & classification (from open-trajectory-gym v9)
# ---------------------------------------------------------------------------

_FLAG_PLACEHOLDERS = frozenset(
    {
        "content_of_flag_here",
        "FLAG{...}",
        "",
        "CHECK",
        "gctf{DUMMY_FLAG}",
        "flag{this_is_fake_flag}",
    }
)

_KNOWN_TOOL_NAMES = frozenset(
    {
        "shell_command",
        "exec_command",
        "execute_command",
        "python_code",
        "read_file",
        "grep",
        "file_search",
        "submit_flag",
        "flag_found",
        "submit_finding",
        "get_challenge",
        "get_progress",
        "check_services",
        "write_stdin",
        "apply_patch",
        "web_search",
        "list_sessions",
        "close_session",
    }
)

_SHELL_WRAPPERS = frozenset(
    {
        "shell_command",
        "exec_command",
        "execute_command",
    }
)

_FLAG_TOOLS = frozenset({"submit_flag", "flag_found"})

_RECON_BINARIES = frozenset(
    {
        "nmap",
        "masscan",
        "ping",
        "traceroute",
        "whois",
        "dig",
        "nslookup",
        "host",
        "smbclient",
        "smbmap",
        "enum4linux",
    }
)
_ENUM_BINARIES = frozenset(
    {
        "curl",
        "wget",
        "gobuster",
        "ffuf",
        "dirb",
        "nikto",
        "ls",
        "cat",
        "head",
        "tail",
        "find",
        "grep",
        "strings",
        "file",
        "id",
        "whoami",
        "ps",
        "env",
        "uname",
        "hostname",
        "ip",
        "ifconfig",
        "netstat",
        "ss",
        "xxd",
        "hexdump",
    }
)
_EXPLOIT_BINARIES = frozenset(
    {
        "sqlmap",
        "hydra",
        "john",
        "hashcat",
        "python",
        "python3",
        "ruby",
        "perl",
        "gcc",
        "nc",
        "ncat",
        "netcat",
        "ssh",
        "msfconsole",
        "msfvenom",
        "chmod",
        "gdb",
        "bash",
        "php",
    }
)

# OpenEnv tool definitions (activates qwen3_coder format in chat template)
OPENENV_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "shell_command",
            "description": "Execute a shell command",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "python_code",
            "description": "Execute Python code",
            "parameters": {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_flag",
            "description": "Submit a captured flag",
            "parameters": {
                "type": "object",
                "properties": {"flag": {"type": "string"}},
                "required": ["flag"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_finding",
            "description": "Submit a security finding",
            "parameters": {
                "type": "object",
                "properties": {"description": {"type": "string"}},
                "required": ["description"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_challenge",
            "description": "Get challenge briefing",
            "parameters": {
                "type": "object",
                "properties": {"role": {"type": "string", "default": "red"}},
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_progress",
            "description": "Get current progress",
            "parameters": {"type": "object", "properties": {}},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_services",
            "description": "Check service health",
            "parameters": {"type": "object", "properties": {}},
        },
    },
]

_reward_rng = random.Random(3407)


def parse_tool_calls(text):
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    calls = []
    for m in _TOOL_CALL_RE.finditer(text):
        name = m.group(1)
        body = m.group(2)
        args = {}
        for pm in _PARAM_RE.finditer(body):
            args[pm.group(1)] = pm.group(2).strip()
        calls.append({"name": name, "arguments": args})
    return calls


def extract_flags(text):
    return _FLAG_RE.findall(text)


def completion_to_text(c):
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(
            m.get("content", "") if isinstance(m, dict) else str(m) for m in c
        )
    return str(c)


def is_real_flag(flag):
    if not flag:
        return False
    if flag in _FLAG_PLACEHOLDERS:
        return False
    for poison in (
        "content_of_flag_here",
        "dummy_flag",
        "fake_flag",
        "this_is_fake",
        "placeholder",
    ):
        if poison in flag.lower():
            return False
    return True


def action_fingerprint(tc):
    name = tc.get("name", "")
    if name in _SHELL_WRAPPERS:
        args = tc.get("arguments", {})
        cmd = (
            args.get("command", args.get("code", "")) if isinstance(args, dict) else ""
        )
        if cmd:
            binary = cmd.split()[0].rsplit("/", 1)[-1].lower()
            return f"{name}:{binary}"
    return name


# ---------------------------------------------------------------------------
# Reward functions (v9: flag=0.85, efficiency=0.10, format=0.05)
# ---------------------------------------------------------------------------


def binary_reward_fn(completions, **kwargs):
    """1.0 if correct flag found, else 0.0. Filters placeholder flags."""
    gts = kwargs.get("ground_truth", [])
    rewards = []
    for i, c in enumerate(completions):
        gt = gts[i] if i < len(gts) else ""
        if not gt or not is_real_flag(gt):
            rewards.append(0.0)
            continue
        text = completion_to_text(c)

        found = False
        for tc in parse_tool_calls(text):
            if tc["name"] in _FLAG_TOOLS:
                sub = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                if sub.strip() == gt.strip():
                    found = True
                    break
        if not found:
            has_flag_tool = any(
                tc["name"] in _FLAG_TOOLS for tc in parse_tool_calls(text)
            )
            if has_flag_tool:
                found = any(f.strip() == gt.strip() for f in extract_flags(text))
        rewards.append(1.0 if found else 0.0)
    return rewards


def online_reward_fn(completions, **kwargs):
    """Online reward: execute tool calls against live OpenEnv server.

    Parses qwen3_coder XML tool calls from completions, replays them
    against the OpenEnv /reset + /step endpoints, returns cumulative reward.
    Falls back to progressive_reward_fn on connection errors.
    """
    import urllib.request
    import urllib.error

    env_url = os.environ.get("OPENENV_URL", "http://localhost:8000")
    gts = kwargs.get("ground_truth", [])
    rewards = []

    for i, c in enumerate(completions):
        gt = gts[i] if i < len(gts) else ""
        text = completion_to_text(c)
        tcs = parse_tool_calls(text)

        if not tcs:
            rewards.append(0.0)
            continue

        try:
            # Reset environment for this episode
            req = urllib.request.Request(
                f"{env_url}/reset",
                data=json.dumps({}).encode(),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)

            episode_reward = 0.0

            for tc in tcs:
                name = tc["name"]
                args = tc.get("arguments", {})

                # Map tool calls to shell commands for RangeAction
                if name in ("shell_command", "exec_command", "execute_command"):
                    command = args.get("command", "")
                elif name in ("submit_flag", "flag_found"):
                    flag_val = args.get("flag", args.get("value", ""))
                    command = f"submit_flag {flag_val}"
                elif name == "python_code":
                    code = args.get("code", "")
                    command = f"python3 -c {json.dumps(code)}"
                elif name == "read_file":
                    command = f"cat {args.get('path', '')}"
                elif name == "get_challenge":
                    command = "get_challenge"
                elif name == "check_services":
                    command = "check_services"
                elif name == "get_progress":
                    command = "get_progress"
                elif name == "submit_finding":
                    command = f"submit_finding {args.get('description', '')}"
                else:
                    command = f"{name} {' '.join(str(v) for v in args.values())}"

                if not command.strip():
                    continue

                step_req = urllib.request.Request(
                    f"{env_url}/step",
                    data=json.dumps(
                        {"action": {"command": command, "mode": "red"}}
                    ).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                resp = urllib.request.urlopen(step_req, timeout=30)
                data = json.loads(resp.read())

                step_reward = data.get("reward", 0) or 0
                episode_reward += float(step_reward)

                if data.get("done", False):
                    break

            # Bonus noise for variance
            episode_reward += _reward_rng.uniform(-0.01, 0.01)
            rewards.append(max(episode_reward, -1.0))

        except (urllib.error.URLError, TimeoutError, OSError) as e:
            logger.warning(
                "Online reward failed for sample %d: %s. Falling back.", i, e
            )
            # Fall back to offline progressive scoring
            fallback = progressive_reward_fn([c], ground_truth=[gt])
            rewards.append(fallback[0])

    return rewards


def progressive_reward_fn(completions, **kwargs):
    """v9 production: flag(0.85) + efficiency(0.10) + format(0.05).

    Physics-inspired efficiency, hallucination energy loss, premature penalty,
    near-miss tolerance, minimum work gate, noise for variance guarantee.
    """
    gts = kwargs.get("ground_truth", [])
    opt_steps_list = kwargs.get("optimal_steps", [])
    rewards = []

    for i, c in enumerate(completions):
        gt = gts[i] if i < len(gts) else ""
        opt_steps = opt_steps_list[i] if i < len(opt_steps_list) else None
        text = completion_to_text(c)
        tcs = parse_tool_calls(text)

        # --- Flag score ---
        flag_sc = 0.0
        if gt and is_real_flag(gt):
            has_flag_tool = False
            for tc in tcs:
                if tc["name"] in _FLAG_TOOLS:
                    has_flag_tool = True
                    sub = tc["arguments"].get("flag", tc["arguments"].get("value", ""))
                    if sub.strip() == gt.strip():
                        flag_sc = 1.0
                        break
            if flag_sc < 1.0 and has_flag_tool and gt in text:
                flag_sc = 1.0
            if flag_sc < 1.0 and re.search(r"FLAG\{[a-zA-Z0-9_-]+\}", text):
                flag_sc = 0.1

        # --- Efficiency score (physics-inspired) ---
        eff_sc = 0.0
        n_calls = len(tcs)
        if n_calls >= 3:
            opt = opt_steps or 10
            step_ratio = min(opt / n_calls, 1.0)
            fingerprints = [action_fingerprint(tc) for tc in tcs]
            novelty = (
                len(set(fingerprints)) / len(fingerprints) if fingerprints else 1.0
            )
            excess = max(0, n_calls - opt) / max(opt, 1)
            time_decay = math.exp(-0.3 * excess)
            eff_sc = step_ratio * novelty * time_decay
            if flag_sc < 1.0:
                eff_sc = min(eff_sc, 0.3)

        # --- Format score (known tools only) ---
        fmt_sc = 0.0
        if tcs:
            valid = 0
            known_count = 0
            for tc in tcs:
                if tc.get("name", "") in _KNOWN_TOOL_NAMES:
                    known_count += 1
                    args = tc.get("arguments", {})
                    if isinstance(args, dict) and args:
                        valid += 1
                    elif args:
                        valid += 0.5
            if known_count > 0:
                fmt_sc = min(valid / known_count, 1.0)

        # Minimum work gate
        if n_calls < 3:
            fmt_sc = min(fmt_sc, 0.3)

        # --- Hallucination penalty (energy loss) ---
        hall_sc = 0.0
        if flag_sc < 1.0:
            for tc in tcs:
                if tc["name"] in _FLAG_TOOLS:
                    hall_sc = -0.20
                    premature_mult = 1.0 + max(0.0, 1.0 - n_calls / 5.0)
                    hall_sc *= premature_mult
                    if gt and is_real_flag(gt):
                        submitted = tc["arguments"].get(
                            "flag", tc["arguments"].get("value", "")
                        )
                        if submitted:
                            sim = difflib.SequenceMatcher(
                                None, submitted.strip(), gt.strip()
                            ).ratio()
                            if sim >= 0.8:
                                hall_sc *= 0.1
                    break

        # Hallucination decays process signals
        if hall_sc < 0:
            eff_sc *= 0.3
            fmt_sc *= 0.3

        # --- Weighted sum ---
        score = 0.85 * flag_sc + 0.10 * eff_sc + 0.05 * fmt_sc + hall_sc
        score += _reward_rng.uniform(-0.01, 0.01)

        rewards.append(max(score, -1.0))
    return rewards


# ---------------------------------------------------------------------------
# OpenAI → qwen3_coder conversion
# ---------------------------------------------------------------------------


def convert_messages(messages):
    converted = []
    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "") or ""
        tool_calls = msg.get("tool_calls")

        if role == "assistant" and tool_calls:
            parts = []
            for tc in tool_calls:
                func = tc.get("function", {})
                name = func.get("name", "unknown")
                args_raw = func.get("arguments", "{}")
                args = json.loads(args_raw) if isinstance(args_raw, str) else args_raw
                params = "\n".join(
                    f"<parameter={k}>{v}</parameter>" for k, v in args.items()
                )
                parts.append(
                    f"<tool_call>\n<function={name}>\n{params}\n</function>\n</tool_call>"
                )
            xml = "\n".join(parts)
            full = f"{content}\n\n{xml}" if content else xml
            converted.append({"role": "assistant", "content": full})
        elif role == "tool":
            converted.append(
                {
                    "role": "user",
                    "content": f"<tool_response>\n{content}\n</tool_response>",
                }
            )
        elif role in ("system", "user", "assistant"):
            converted.append({"role": role, "content": content})
    return converted


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Unsloth GRPO for CTF training")
    parser.add_argument("--model", default=MODEL)
    parser.add_argument("--data", default=DATA)
    parser.add_argument("--output", default=OUTPUT)
    parser.add_argument(
        "--reward",
        default="online",
        choices=["binary", "progressive", "online", "both"],
    )
    parser.add_argument(
        "--env-url",
        default="http://localhost:8000",
        help="OpenEnv server URL for online reward",
    )
    parser.add_argument("--seq", type=int, default=SEQ)
    parser.add_argument("--comp-len", type=int, default=COMP_LEN)
    parser.add_argument("--num-gen", type=int, default=NUM_GEN)
    parser.add_argument("--epochs", type=int, default=EPOCHS)
    args = parser.parse_args()

    logger.info("=== Unsloth GRPO Training ===")
    logger.info("Model: %s", args.model)
    logger.info("Data: %s", args.data)
    logger.info("Reward: %s", args.reward)

    # Check model exists
    if not Path(args.model).exists():
        logger.error("Model not found: %s. Run SFT first.", args.model)
        sys.exit(1)

    # Load data
    data_path = Path(args.data)
    if not data_path.exists():
        logger.error("Data not found: %s", args.data)
        sys.exit(1)

    records = []
    with open(data_path) as f:
        for line in f:
            line = line.strip()
            if line:
                records.append(json.loads(line))
    logger.info("Loaded %d records", len(records))

    # Import Unsloth
    from unsloth import FastLanguageModel

    # ------------------------------------------------------------------
    # Monkey-patch: Qwen3.5 compute_3d_position_ids rope_deltas crash
    # When rope_deltas is set to an empty tensor from a previous forward
    # pass, text-only batches enter the wrong branch and crash with a
    # shape mismatch.  Guard: treat empty rope_deltas as None.
    # ------------------------------------------------------------------
    try:
        from transformers.models.qwen3_5.modeling_qwen3_5 import Qwen3_5Model

        _orig_compute_3d = Qwen3_5Model.compute_3d_position_ids

        def _patched_compute_3d(self, *args, **kwargs):
            if self.rope_deltas is not None and self.rope_deltas.numel() == 0:
                self.rope_deltas = None
            return _orig_compute_3d(self, *args, **kwargs)

        Qwen3_5Model.compute_3d_position_ids = _patched_compute_3d
        logger.info("Patched Qwen3_5Model.compute_3d_position_ids (rope_deltas guard)")
    except Exception as e:
        logger.warning("Could not patch Qwen3.5 rope_deltas: %s", e)

    # Load model (no fast_inference — TRL 0.24.0 incompatible with vLLM 0.17.0)
    logger.info("Loading model (HF generate, no vLLM)...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=args.model,
        max_seq_length=args.seq,
        load_in_4bit=False,
        load_in_16bit=True,
        full_finetuning=False,
        dtype=None,
    )

    # Fix tokenizer (Qwen3.5 may return processor)
    tok = tokenizer.tokenizer if hasattr(tokenizer, "tokenizer") else tokenizer

    # Prepare prompts
    prompts = []
    ground_truths = []
    for r in records:
        msgs = r.get("messages", [])
        prompt_msgs = [m for m in msgs if m.get("role") in ("system", "user")]
        if not prompt_msgs:
            continue

        gt = r.get("ground_truth_flag", "")
        if gt and not is_real_flag(gt):
            logger.warning("Skipped placeholder flag: %s", gt)
            continue

        converted = convert_messages(prompt_msgs)
        try:
            text = tok.apply_chat_template(
                converted,
                tools=OPENENV_TOOLS,  # CRITICAL: activates qwen3_coder XML format
                tokenize=False,
                add_generation_prompt=True,
            )
            prompts.append(text)
            ground_truths.append(gt)
        except Exception as e:
            logger.warning("Skipped: %s", e)

    logger.info("Prepared %d prompts", len(prompts))
    if not prompts:
        logger.error("No valid prompts!")
        sys.exit(1)

    # Apply LoRA
    logger.info("Applying LoRA (r=%d, alpha=%d)", LORA_R, LORA_ALPHA)
    model = FastLanguageModel.get_peft_model(
        model,
        r=LORA_R,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        lora_alpha=LORA_ALPHA,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
        max_seq_length=args.seq,
    )

    # Create dataset
    from datasets import Dataset

    ds = Dataset.from_dict(
        {
            "prompt": prompts,
            "ground_truth": ground_truths,
        }
    )

    # Select reward
    if args.reward == "online":
        os.environ["OPENENV_URL"] = args.env_url
        reward_funcs = [online_reward_fn]
        logger.info("Online reward: %s", args.env_url)
    elif args.reward == "binary":
        reward_funcs = [binary_reward_fn]
    elif args.reward == "both":
        reward_funcs = [binary_reward_fn, progressive_reward_fn]
    else:
        reward_funcs = [progressive_reward_fn]

    logger.info("Reward functions: %s", [f.__name__ for f in reward_funcs])

    # Train
    from trl import GRPOTrainer, GRPOConfig

    logger.info("Starting GRPO training...")
    trainer = GRPOTrainer(
        model=model,
        processing_class=tok,
        reward_funcs=reward_funcs,
        args=GRPOConfig(
            output_dir=args.output,
            num_generations=args.num_gen,
            max_completion_length=args.comp_len,
            per_device_train_batch_size=BATCH,
            gradient_accumulation_steps=GRAD_ACCUM,
            num_train_epochs=args.epochs,
            warmup_steps=10,
            learning_rate=LR,
            weight_decay=0.01,
            lr_scheduler_type="cosine",
            logging_steps=1,
            save_steps=25,
            save_total_limit=2,
            seed=3407,
            bf16=True,
            report_to="none",
            beta=BETA,
            temperature=TEMP,
        ),
        train_dataset=ds,
    )

    stats = trainer.train()
    logger.info("GRPO complete! Loss: %.4f", stats.training_loss)

    # Save
    final_dir = str(Path(args.output) / "final")
    logger.info("Saving LoRA to %s", final_dir)
    model.save_pretrained(final_dir)
    tok.save_pretrained(final_dir)

    # Merge
    merge_dir = str(Path(args.output) / "merged")
    logger.info("Merging to %s", merge_dir)
    model.save_pretrained_merged(merge_dir, tok, save_method="merged_16bit")

    logger.info("=== GRPO Training Complete ===")
    logger.info("  Loss: %.4f", stats.training_loss)
    logger.info("  LoRA: %s", final_dir)
    logger.info("  Merged: %s", merge_dir)


if __name__ == "__main__":
    main()
