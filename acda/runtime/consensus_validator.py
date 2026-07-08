"""
ACDA-SDK — Consensus Validation Engine

Implements multiple consensus algorithms to validate AI model outputs
before any defense action is authorized.

Algorithms:
  - weighted_vote   : Σ(weight × confidence) ≥ threshold
  - majority_vote   : simple majority (≥ 50% of models agree)
  - unanimous       : all models must agree
  - quorum          : configurable quorum fraction

This is the core safety gate of the entire system.
"""

from __future__ import annotations

import asyncio
from enum import Enum
from typing import Dict, List, Optional

import structlog

from acda.models.schemas import (
    ConsensusConfig,
    ConsensusMethod,
    ConsensusResult,
    ModelScore,
    ReasoningResult,
)

logger = structlog.get_logger(__name__)


class ConsensusValidator:
    """
    Validates multi-model AI reasoning results.

    Usage:
        validator = ConsensusValidator(
            method="weighted_vote",
            threshold=0.80,
            weights={"model_A": 0.4, "model_B": 0.35, "model_C": 0.25},
        )
        result = await validator.validate(reasoning_result)
        if result.passed:
            # Safe to execute defense actions
    """

    def __init__(
        self,
        method: str = "weighted_vote",
        threshold: float = 0.80,
        weights: Optional[Dict[str, float]] = None,
        min_models_required: int = 2,
        timeout_seconds: int = 30,
    ) -> None:
        self.method = ConsensusMethod(method)
        self.threshold = threshold
        self.weights = weights or {}
        self.min_models_required = min_models_required
        self.timeout_seconds = timeout_seconds

    # ─────────────────────────────────────────────────────────

    async def validate(self, reasoning: ReasoningResult) -> ConsensusResult:
        """Run consensus validation against reasoning scores."""

        scores = reasoning.scores

        if len(scores) < self.min_models_required:
            return ConsensusResult(
                passed=False,
                score=0.0,
                threshold=self.threshold,
                method=self.method.value,
                model_votes=scores,
                explanation=(
                    f"Insufficient models: got {len(scores)}, "
                    f"need ≥ {self.min_models_required}."
                ),
            )

        try:
            async with asyncio.timeout(self.timeout_seconds):
                if self.method == ConsensusMethod.WEIGHTED_VOTE:
                    return self._weighted_vote(scores)
                elif self.method == ConsensusMethod.MAJORITY_VOTE:
                    return self._majority_vote(scores)
                elif self.method == ConsensusMethod.UNANIMOUS:
                    return self._unanimous(scores)
                elif self.method == ConsensusMethod.QUORUM:
                    return self._quorum(scores)
                else:
                    raise ValueError(f"Unknown consensus method: {self.method}")

        except asyncio.TimeoutError:
            logger.error(
                "consensus_timeout", method=self.method, timeout=self.timeout_seconds
            )
            return ConsensusResult(
                passed=False,
                score=0.0,
                threshold=self.threshold,
                method=self.method.value,
                model_votes=scores,
                explanation=f"Consensus timed out after {self.timeout_seconds}s.",
            )

    # ─── Weighted Vote ────────────────────────────────────────

    def _weighted_vote(self, scores: List[ModelScore]) -> ConsensusResult:
        """
        ConsensusScore = Σ (weight_i × confidence_i)
        Actions executed only when ConsensusScore ≥ threshold.
        """
        # Build weight map (fall back to equal weights if not configured)
        weight_map = dict(self.weights)
        if not weight_map:
            n = len(scores)
            equal_w = round(1.0 / n, 6) if n else 0.0
            weight_map = {s.model_id: equal_w for s in scores}

        total_weight = sum(weight_map.values())
        if total_weight == 0:
            total_weight = 1.0  # avoid div-by-zero

        weighted_sum = 0.0
        breakdown = []

        for s in scores:
            w = weight_map.get(s.model_id, 0.0)
            contribution = w * s.confidence
            weighted_sum += contribution
            breakdown.append(
                f"{s.model_id}: score={s.score:.3f} confidence={s.confidence:.3f} "
                f"weight={w:.3f} contribution={contribution:.4f}"
            )

        consensus_score = weighted_sum / total_weight
        passed = consensus_score >= self.threshold

        explanation = (
            f"Weighted vote: {consensus_score:.4f} "
            f"{'≥' if passed else '<'} threshold={self.threshold:.2f}. "
            f"| {' | '.join(breakdown)}"
        )

        logger.info(
            "consensus_weighted_vote",
            score=round(consensus_score, 4),
            threshold=self.threshold,
            passed=passed,
        )

        return ConsensusResult(
            passed=passed,
            score=consensus_score,
            threshold=self.threshold,
            method=self.method.value,
            model_votes=scores,
            explanation=explanation,
        )

    # ─── Majority Vote ────────────────────────────────────────

    def _majority_vote(self, scores: List[ModelScore]) -> ConsensusResult:
        """
        Simple majority: more than half the models must score ≥ threshold.
        """
        agreeing = [s for s in scores if s.score >= self.threshold]
        majority_fraction = len(agreeing) / len(scores) if scores else 0.0
        passed = majority_fraction > 0.5

        explanation = (
            f"Majority vote: {len(agreeing)}/{len(scores)} models agree "
            f"({majority_fraction:.1%}). Passed={passed}"
        )

        return ConsensusResult(
            passed=passed,
            score=majority_fraction,
            threshold=self.threshold,
            method=self.method.value,
            model_votes=scores,
            explanation=explanation,
        )

    # ─── Unanimous ────────────────────────────────────────────

    def _unanimous(self, scores: List[ModelScore]) -> ConsensusResult:
        """All models must score ≥ threshold."""
        passing = [s for s in scores if s.score >= self.threshold]
        passed = len(passing) == len(scores)

        explanation = (
            f"Unanimous vote: {len(passing)}/{len(scores)} models passed. "
            f"Unanimous={passed}"
        )

        aggregate = sum(s.score for s in scores) / len(scores) if scores else 0.0

        return ConsensusResult(
            passed=passed,
            score=aggregate,
            threshold=self.threshold,
            method=self.method.value,
            model_votes=scores,
            explanation=explanation,
        )

    # ─── Quorum ───────────────────────────────────────────────

    def _quorum(
        self, scores: List[ModelScore], quorum_fraction: float = 0.67
    ) -> ConsensusResult:
        """Configurable quorum: ≥ quorum_fraction of models must agree."""
        agreeing = [s for s in scores if s.score >= self.threshold]
        actual_fraction = len(agreeing) / len(scores) if scores else 0.0
        passed = actual_fraction >= quorum_fraction

        explanation = (
            f"Quorum vote: {len(agreeing)}/{len(scores)} agree "
            f"({actual_fraction:.1%} ≥ quorum={quorum_fraction:.0%}). Passed={passed}"
        )

        return ConsensusResult(
            passed=passed,
            score=actual_fraction,
            threshold=self.threshold,
            method=self.method.value,
            model_votes=scores,
            explanation=explanation,
        )

    # ─────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config: ConsensusConfig) -> "ConsensusValidator":
        return cls(
            method=config.method,
            threshold=config.threshold,
            weights=config.weights or {},
            min_models_required=config.min_models_required,
            timeout_seconds=config.timeout_seconds,
        )
