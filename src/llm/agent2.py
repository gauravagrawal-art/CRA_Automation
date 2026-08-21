"""Agent 2 provider protocol — narrative explanation only.

Agent 2 is the single LLM-dependent part of Flow 3. It receives a minimal
payload and returns three prose fields. It cannot reach a verdict, a severity,
an identifier or a hash, because the application never reads those back from a
provider.

No concrete provider ships with the POC. ``NullAgent2Provider`` keeps the
narration path exercisable without a model, mirroring ``NullProvider`` in
``src.llm.provider``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from src.config import PROMPTS_DIR

AGENT2_PROMPT_PATH: Path = PROMPTS_DIR / "agent2_assessment_reporting.md"

#: The only keys the application will read back from a provider.
NARRATIVE_FIELDS = ("expected_state", "observed_state", "reason")


class Agent2Provider(ABC):
    """Explains one prepared control result."""

    @abstractmethod
    def explain(self, *, system_prompt: str, payload: dict[str, Any]) -> dict[str, str]:
        """Return narrative fields for the supplied control payload.

        Only the keys in ``NARRATIVE_FIELDS`` are honoured. Raising is a
        supported outcome: the caller falls back to template narration.
        """
        ...


class NullAgent2Provider(Agent2Provider):
    """Default provider — declines to narrate, so templates are used."""

    def explain(self, *, system_prompt: str, payload: dict[str, Any]) -> dict[str, str]:
        return {}


def load_agent2_prompt(path: Path | None = None) -> str:
    """Read the Agent 2 system prompt from disk."""
    prompt_path = path or AGENT2_PROMPT_PATH
    if not prompt_path.exists():
        raise FileNotFoundError(f"Agent 2 prompt not found: {prompt_path}")
    return prompt_path.read_text()
