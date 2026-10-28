#!/usr/bin/env python3
#=============================================================================
# Guardrail Step Monitor — streaming reasoning-step safety monitor
#=============================================================================
# Research finding (Beyond Content Safety): a Reasoning Safety Monitor runs in
# parallel with the target LLM, inspecting each reasoning step as it is
# generated in a streaming fashion. On detecting an unsafe step it dispatches
# an interrupt signal to halt generation before corrupted reasoning propagates
# to the final answer or exhausts compute budgets.
#
# Design:
#   - Target LLM generates reasoning in a streaming fashion.
#   - Monitor treats each segment delimited by double newline (\n\n) as an
#     atomic reasoning step.
#   - Each step is checked against the guardrail engine (container breakout,
#     harmful content, PII, exfiltration, system-prompt leakage, jailbreak).
#   - On an unsafe step: emit an interrupt, halt further generation, return
#     the safe prefix + a refusal.
#   - Maintains a rolling context window (problem statement + preceding steps)
#     for cross-step consistency / goal-deviation checks.
#=============================================================================

import json
import os
from typing import Optional, Dict, Any, List, Tuple, Callable

from guardrail import GuardrailEngine

STEP_DELIM = "\n\n"


class StepMonitorResult:
    """Outcome of monitored reasoning generation."""

    def __init__(self, safe: bool, steps: List[str],
                 interrupted_at: Optional[int],
                 reason: str, blocked_by: Optional[str],
                 sanitized_reasoning: str):
        self.safe = safe
        self.steps = steps
        self.interrupted_at = interrupted_at  # step index where it stopped
        self.reason = reason
        self.blocked_by = blocked_by
        self.sanitized_reasoning = sanitized_reasoning

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "steps": self.steps,
            "interrupted_at": self.interrupted_at,
            "reason": self.reason,
            "blocked_by": self.blocked_by,
            "sanitized_reasoning": self.sanitized_reasoning,
        }


class ReasoningStepMonitor:
    """Streaming step-level safety monitor for chain-of-thought reasoning."""

    def __init__(self, engine: Optional[GuardrailEngine] = None,
                 max_steps: int = 50,
                 interrupt_on_unsafe: bool = True):
        self.engine = engine or GuardrailEngine()
        self.max_steps = max_steps
        self.interrupt_on_unsafe = interrupt_on_unsafe
        self.stats = {"steps_monitored": 0, "steps_blocked": 0,
                      "interruptions": 0}

    def monitor_stream(self, step_generator: Callable[[], str],
                       page_id: str = "default",
                       agent_name: str = "assistant",
                       problem_statement: str = "") -> StepMonitorResult:
        """Consume a stream of reasoning text chunks, segment into steps,
        and check each step against the guardrail engine.

        step_generator: a callable that returns the next chunk of text, or
                        None/"" when the stream is exhausted.
        """
        steps: List[str] = []
        current_step_buffer = ""
        full_reasoning = ""
        interrupted_at: Optional[int] = None
        block_reason = ""
        block_by: Optional[str] = None
        step_index = 0

        # Rolling context for cross-step checks.
        context_parts = []
        if problem_statement:
            context_parts.append(f"PROBLEM: {problem_statement}")

        while True:
            try:
                chunk = step_generator()
            except StopIteration:
                chunk = None
            if not chunk:
                # Flush any remaining buffer as a final step.
                if current_step_buffer.strip():
                    step_text = current_step_buffer.strip()
                    res = self._check_step(
                        step_text, context_parts, page_id, agent_name)
                    steps.append(step_text)
                    full_reasoning += step_text + STEP_DELIM
                    self.stats["steps_monitored"] += 1
                    if not res[0]:
                        interrupted_at = step_index
                        block_reason = res[1]
                        block_by = res[2]
                        self.stats["steps_blocked"] += 1
                        self.stats["interruptions"] += 1
                        break
                    step_index += 1
                    context_parts.append(f"STEP {step_index}: {step_text}")
                break

            current_step_buffer += chunk
            # Split on double-newline delimiters to find complete steps.
            while STEP_DELIM in current_step_buffer:
                step_text, current_step_buffer = current_step_buffer.split(
                    STEP_DELIM, 1)
                step_text = step_text.strip()
                if not step_text:
                    continue
                res = self._check_step(
                    step_text, context_parts, page_id, agent_name)
                steps.append(step_text)
                full_reasoning += step_text + STEP_DELIM
                self.stats["steps_monitored"] += 1
                if not res[0]:
                    interrupted_at = step_index
                    block_reason = res[1]
                    block_by = res[2]
                    self.stats["steps_blocked"] += 1
                    self.stats["interruptions"] += 1
                    return StepMonitorResult(
                        safe=False, steps=steps,
                        interrupted_at=interrupted_at,
                        reason=block_reason, blocked_by=block_by,
                        sanitized_reasoning=full_reasoning)
                step_index += 1
                context_parts.append(f"STEP {step_index}: {step_text}")
                # Keep rolling window bounded.
                if len(context_parts) > 10:
                    context_parts = context_parts[-10:]

            if step_index >= self.max_steps:
                break

        return StepMonitorResult(
            safe=True, steps=steps,
            interrupted_at=None, reason="All reasoning steps passed",
            blocked_by=None,
            sanitized_reasoning=full_reasoning)

    def _check_step(self, step_text: str, context_parts: List[str],
                    page_id: str, agent_name: str) -> Tuple[bool, str, str]:
        """Check a single reasoning step against the guardrail engine."""
        # Combine step with rolling context for cross-step consistency.
        context = STEP_DELIM.join(context_parts) if context_parts else ""
        combined = (f"{context}{STEP_DELIM}STEP: {step_text}"
                    if context else step_text)

        # Run the full guardrail input check on the step.
        res = self.engine.validate_input(combined, page_id=page_id,
                                         agent_name=agent_name)
        if not res["safe"]:
            return (False,
                    res.get("reason", "step blocked"),
                    res.get("blocked_by"))

        # Additional: check the raw step text too (in case context
        # dilutes a pattern match).
        raw_res = self.engine.validate_input(step_text, page_id=page_id,
                                             agent_name=agent_name)
        if not raw_res["safe"]:
            return (False,
                    raw_res.get("reason", "step blocked"),
                    raw_res.get("blocked_by"))

        return True, "step passed", None

    def get_stats(self) -> Dict[str, Any]:
        return dict(self.stats)


# ── Convenience: monitor a full reasoning string (non-streaming) ─────────

def monitor_reasoning(reasoning: str, page_id: str = "default",
                      agent_name: str = "assistant",
                      problem_statement: str = "",
                      engine: Optional[GuardrailEngine] = None,
                      interrupt_on_unsafe: bool = True) -> StepMonitorResult:
    """Split a complete reasoning string into steps and monitor each."""
    monitor = ReasoningStepMonitor(engine=engine,
                                   interrupt_on_unsafe=interrupt_on_unsafe)

    def gen():
        # Yield chunks split on double newlines.
        parts = reasoning.split(STEP_DELIM)
        for i, p in enumerate(parts):
            yield p + (STEP_DELIM if i < len(parts) - 1 else "")
        return  # generator ends

    g = gen()

    def next_chunk():
        try:
            return next(g)
        except StopIteration:
            return None

    return monitor.monitor_stream(next_chunk, page_id, agent_name,
                                  problem_statement)
