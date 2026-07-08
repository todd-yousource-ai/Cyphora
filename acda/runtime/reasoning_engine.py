"""
ACDA-SDK — Reasoning Engine

Dispatches security data to multiple AI models in parallel,
collects scored outputs, and packages them for consensus validation.

BUG 7 FIX: Individual model scores, labels, confidences, and latencies
are now logged per-model in the 'model_scores' field of the
reasoning_complete log event.  Previously only avg_score was emitted,
making post-hoc audit of AI decisions impossible.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import structlog

from acda.models.schemas import CollectedData, ModelScore, ReasoningResult

logger = structlog.get_logger(__name__)


class BaseModelAdapter(ABC):
    def __init__(self, model_id: str) -> None:
        self.model_id = model_id

    @abstractmethod
    async def analyze(
        self,
        task: str,
        data: Dict[str, Any],
        system_prompt: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 2048,
    ) -> ModelScore: ...


class OpenAIModelAdapter(BaseModelAdapter):
    def __init__(self, model_id: str, api_key: Optional[str] = None) -> None:
        super().__init__(model_id)
        self._api_key = api_key

    async def analyze(self, task, data, system_prompt=None, temperature=0.2, max_tokens=2048):
        try:
            import openai
            client = openai.AsyncOpenAI(api_key=self._api_key)
        except ImportError:
            logger.warning("openai_not_installed", model=self.model_id)
            return self._fallback_score()

        prompt = _build_analysis_prompt(task, data)
        start = time.perf_counter()
        try:
            response = await client.chat.completions.create(
                model=self.model_id,
                messages=[
                    {"role": "system", "content": system_prompt or _default_system_prompt(task)},
                    {"role": "user", "content": prompt},
                ],
                temperature=temperature,
                max_tokens=max_tokens,
                response_format={"type": "json_object"},
            )
            latency_ms = (time.perf_counter() - start) * 1000
            raw_text = response.choices[0].message.content or "{}"
            return _parse_model_response(self.model_id, raw_text, task, latency_ms)
        except Exception as exc:
            logger.error("openai_error", model=self.model_id, error=str(exc))
            return self._fallback_score()

    def _fallback_score(self) -> ModelScore:
        return ModelScore(model_id=self.model_id, score=0.0, label="error",
                          confidence=0.0, reasoning="Model unavailable")


class AnthropicModelAdapter(BaseModelAdapter):
    def __init__(self, model_id: str, api_key: Optional[str] = None) -> None:
        super().__init__(model_id)
        self._api_key = api_key

    async def analyze(self, task, data, system_prompt=None, temperature=0.2, max_tokens=2048):
        try:
            import anthropic
            client = anthropic.AsyncAnthropic(api_key=self._api_key)
        except ImportError:
            logger.warning("anthropic_not_installed", model=self.model_id)
            return ModelScore(model_id=self.model_id, score=0.0, label="error",
                              confidence=0.0, reasoning="anthropic SDK not installed")

        prompt = _build_analysis_prompt(task, data)
        start = time.perf_counter()
        try:
            response = await client.messages.create(
                model=self.model_id,
                max_tokens=max_tokens,
                system=system_prompt or _default_system_prompt(task),
                messages=[{"role": "user", "content": prompt}],
            )
            latency_ms = (time.perf_counter() - start) * 1000
            raw_text = response.content[0].text if response.content else "{}"
            return _parse_model_response(self.model_id, raw_text, task, latency_ms)
        except Exception as exc:
            logger.error("anthropic_error", model=self.model_id, error=str(exc))
            return ModelScore(model_id=self.model_id, score=0.0, label="error",
                              confidence=0.0, reasoning=str(exc))


class SimulationModelAdapter(BaseModelAdapter):
    def __init__(self, model_id: str, fixed_score: float = 0.85) -> None:
        super().__init__(model_id)
        self._fixed_score = fixed_score

    async def analyze(self, task, data, system_prompt=None, temperature=0.2, max_tokens=2048):
        await asyncio.sleep(0.05)
        import hashlib
        h = int(hashlib.md5(self.model_id.encode()).hexdigest()[:4], 16)
        variance = (h % 100) / 1000.0
        score = min(1.0, self._fixed_score + variance)
        return ModelScore(
            model_id=self.model_id,
            score=round(score, 4),
            label="threat_detected" if score > 0.5 else "benign",
            confidence=round(score, 4),
            reasoning=f"[SIMULATION] {task} analysis with score {score:.4f}",
            latency_ms=50.0,
        )


def _build_analysis_prompt(task: str, data: Dict[str, Any]) -> str:
    data_str = json.dumps(data, indent=2, default=str)[:4000]
    return (
        f"Security analysis task: {task}\n\n"
        f"Security telemetry data:\n{data_str}\n\n"
        "Respond ONLY with valid JSON in this format:\n"
        '{"score": 0.95, "label": "threat_detected", "confidence": 0.92, "reasoning": "..."}'
    )


def _default_system_prompt(task: str) -> str:
    return (
        "You are an expert cybersecurity AI model performing automated threat analysis. "
        f"Your task is: {task}. "
        "Analyse the provided security telemetry and output a structured JSON assessment. "
        "Score range: 0.0 (benign) to 1.0 (confirmed threat). "
        "Be precise and conservative — only flag high confidence threats."
    )


def _extract_json_object_text(raw_text: str) -> str:
    text = (raw_text or "").strip()
    if not text:
        return text
    fenced = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.DOTALL | re.IGNORECASE)
    if fenced:
        text = fenced.group(1).strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    start = text.find("{")
    if start == -1:
        return text
    depth, in_string, escape = 0, False, False
    for idx in range(start, len(text)):
        ch = text[idx]
        if escape:
            escape = False; continue
        if ch == "\\":
            escape = True; continue
        if ch == '"':
            in_string = not in_string; continue
        if in_string:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start: idx + 1]
    return text


def _parse_model_response(model_id, raw_text, task, latency_ms):
    try:
        parsed = json.loads(_extract_json_object_text(raw_text))
        if not isinstance(parsed, dict):
            raise ValueError(f"Expected JSON object, got {type(parsed).__name__}")
        return ModelScore(
            model_id=model_id,
            score=float(parsed.get("score", 0.0)),
            label=str(parsed.get("label", "unknown")),
            confidence=float(parsed.get("confidence", 0.0)),
            reasoning=str(parsed.get("reasoning", "")),
            latency_ms=latency_ms,
        )
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        preview = (raw_text or "").strip().replace("\n", "\\n")[:240]
        logger.warning("model_response_parse_error", model=model_id, error=str(e), raw_preview=preview)
        return ModelScore(model_id=model_id, score=0.0, label="parse_error",
                          confidence=0.0, reasoning=f"Parse failed: {e}", latency_ms=latency_ms)


_MODEL_PREFIXES = {
    "gpt-": OpenAIModelAdapter,
    "claude-": AnthropicModelAdapter,
    "sim_": SimulationModelAdapter,
    "model_": SimulationModelAdapter,
}


def _create_adapter(model_id: str) -> BaseModelAdapter:
    for prefix, cls in _MODEL_PREFIXES.items():
        if model_id.lower().startswith(prefix):
            return cls(model_id)
    logger.warning("unknown_model_falling_back_to_simulation", model=model_id)
    return SimulationModelAdapter(model_id)


class ReasoningEngine:
    """
    Orchestrates parallel execution of multiple AI models.

    BUG 7 FIX: reasoning_complete log event now includes 'model_scores'
    — a list of per-model dicts containing model_id, score, label,
    confidence, latency_ms, and a reasoning_preview.  This satisfies
    SOC2 CC6.1 and HIPAA §164.312(b) audit requirements for AI decisions.
    """

    def __init__(
        self,
        models: List[str],
        task: str,
        temperature: float = 0.2,
        max_tokens: int = 2048,
        system_prompt: Optional[str] = None,
        timeout_per_model: float = 25.0,
    ) -> None:
        self.task = task
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt
        self.timeout_per_model = timeout_per_model
        self._adapters: List[BaseModelAdapter] = [_create_adapter(m) for m in models]

    async def run(self, data: CollectedData) -> ReasoningResult:
        if not self._adapters:
            logger.warning("no_models_configured_for_reasoning")
            return ReasoningResult(scores=[], task=self.task)

        payload = {
            "event_id": data.event.event_id,
            "event_type": data.event.event_type,
            "source_host": data.event.source_host,
            "source_ip": data.event.source_ip,
            "user": data.event.user,
            "process": data.event.process,
            "severity": data.event.severity,
            "log_count": len(data.logs),
            "logs_sample": data.logs[:20],
            "threat_intel_hits": len(data.threat_intel),
        }

        tasks = [self._run_model_with_timeout(adapter, payload) for adapter in self._adapters]
        scores = await asyncio.gather(*tasks, return_exceptions=False)
        valid_scores = [s for s in scores if isinstance(s, ModelScore)]

        avg_score = (
            round(sum(s.score for s in valid_scores) / len(valid_scores), 4)
            if valid_scores else 0.0
        )

        # ── BUG 7 FIX: emit full per-model audit trail ────────────────
        model_scores_log = [
            {
                "model_id": s.model_id,
                "score": s.score,
                "label": s.label,
                "confidence": s.confidence,
                "latency_ms": round(s.latency_ms or 0.0, 1),
                "reasoning_preview": (s.reasoning or "")[:300],
            }
            for s in valid_scores
        ]

        logger.info(
            "reasoning_complete",
            task=self.task,
            models_run=len(self._adapters),
            models_succeeded=len(valid_scores),
            avg_score=avg_score,
            model_scores=model_scores_log,          # ← NEW: per-model detail
        )
        # ── END BUG 7 FIX ─────────────────────────────────────────────

        return ReasoningResult(scores=valid_scores, task=self.task)

    async def _run_model_with_timeout(self, adapter: BaseModelAdapter, payload: Dict[str, Any]) -> ModelScore:
        try:
            async with asyncio.timeout(self.timeout_per_model):
                return await adapter.analyze(
                    task=self.task, data=payload,
                    system_prompt=self.system_prompt,
                    temperature=self.temperature,
                    max_tokens=self.max_tokens,
                )
        except asyncio.TimeoutError:
            logger.warning("model_timeout", model=adapter.model_id, timeout=self.timeout_per_model)
            return ModelScore(model_id=adapter.model_id, score=0.0, label="timeout",
                              confidence=0.0, reasoning=f"Model timed out after {self.timeout_per_model}s")
        except Exception as exc:
            logger.error("model_exception", model=adapter.model_id, error=str(exc))
            return ModelScore(model_id=adapter.model_id, score=0.0, label="error",
                              confidence=0.0, reasoning=str(exc))
