"""LLM provider protocol and cached assist client."""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.config import PROPOSALS_DIR


@dataclass
class AssistProposal:
    control_id: str
    technical_control: str
    nms_interpretation: str
    model_name: str
    prompt_hash: str
    temperature: float


class LLMProvider(ABC):
    @abstractmethod
    def propose_technical_control(
        self,
        *,
        requirement_text: str,
        etsi_requirement_id: str,
        product_context: str,
    ) -> tuple[str, str]:
        """Return (nms_interpretation, technical_control)."""
        ...


class NullProvider(LLMProvider):
    """Default provider — deterministic pipeline runs without a model."""

    def propose_technical_control(
        self,
        *,
        requirement_text: str,
        etsi_requirement_id: str,
        product_context: str,
    ) -> tuple[str, str]:
        interpretation = (
            f"NMS interpretation for {etsi_requirement_id}: apply requirement to "
            f"NextBoss-XT management plane based on declared product profile."
        )
        technical = (
            f"Verify host-level observable configuration supporting: {requirement_text[:120]}"
        )
        return interpretation, technical


def _prompt_hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class CachedAssistClient:
    """Optional assist — writes to proposals/, never required at runtime."""

    def __init__(
        self,
        provider: LLMProvider | None = None,
        proposals_dir: Path = PROPOSALS_DIR,
        temperature: float = 0.0,
    ):
        self.provider = provider or NullProvider()
        self.proposals_dir = proposals_dir
        self.temperature = temperature
        self.proposals_dir.mkdir(parents=True, exist_ok=True)

    def get_or_propose(
        self,
        *,
        control_id: str,
        requirement_text: str,
        etsi_requirement_id: str,
        product_context: str,
        force_refresh: bool = False,
    ) -> AssistProposal | None:
        cache_path = self.proposals_dir / f"{control_id}.json"
        prompt = f"{requirement_text}|{etsi_requirement_id}|{product_context}"
        phash = _prompt_hash(prompt)

        if cache_path.exists() and not force_refresh:
            cached = json.loads(cache_path.read_text())
            if cached.get("prompt_hash") == phash:
                return AssistProposal(**cached)

        if isinstance(self.provider, NullProvider):
            return None

        interpretation, technical = self.provider.propose_technical_control(
            requirement_text=requirement_text,
            etsi_requirement_id=etsi_requirement_id,
            product_context=product_context,
        )
        proposal = AssistProposal(
            control_id=control_id,
            technical_control=technical,
            nms_interpretation=interpretation,
            model_name=type(self.provider).__name__,
            prompt_hash=phash,
            temperature=self.temperature,
        )
        cache_path.write_text(json.dumps(proposal.__dict__, indent=2))
        return proposal

    def diff_on_regeneration(self, control_id: str, new_proposal: AssistProposal) -> dict[str, Any] | None:
        cache_path = self.proposals_dir / f"{control_id}.json"
        if not cache_path.exists():
            return None
        old = json.loads(cache_path.read_text())
        if old.get("technical_control") != new_proposal.technical_control:
            return {"old": old.get("technical_control"), "new": new_proposal.technical_control}
        return None
