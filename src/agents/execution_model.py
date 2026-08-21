"""Generate agent1_execution_model.md from implementation."""

from __future__ import annotations

from pathlib import Path

from src.config import PROMPTS_DIR

EXECUTION_MODEL = """# Agent 1 Execution Model

Generated from implementation. The base spec prompt is at
`agent1_document_control_intelligence.md`. Enhancement v1.1 appends a
`PRODUCT CONTEXT` section; product and policy YAML are loaded as structured
inputs (not legal sources).

| Step | Name | Mode | Owner Module |
|------|------|------|--------------|
| 1 | Inventory | Deterministic | `src/documents/loader.py` |
| 2 | Extract | Deterministic | `src/documents/parser.py`, `src/documents/cleaner.py` |
| 3 | Identify legal requirements | Deterministic | `src/documents/requirements.py` |
| 4 | Category 6 context | Deterministic | `src/documents/requirements.py` |
| 5 | Supporting interpretation | Deterministic | `src/documents/crosswalk.py`, `src/documents/source_classifier.py` |
| 5b | Load product profile & assertions | Deterministic | `src/product/profile.py`, `src/policy/assertions.py` |
| 6 | Applicability | Deterministic | `src/agents/agent1.py` |
| 7 | Derive technical controls | Model-assisted (optional, cached) | `src/llm/provider.py` |
| 8 | Define evidence | Deterministic | `src/agents/agent1.py`, `src/agents/coverage.py` |
| 9 | Map MCP capabilities | Deterministic | `src/agents/agent1.py`, `src/agents/coverage.py` |
| 9b | Attach target_context & assertion_refs | Deterministic | `src/agents/coverage.py`, `src/agents/agent1.py` |
| 10 | Assessment rules | Deterministic | `src/rules/dsl.py`, `src/agents/coverage.py`, `src/agents/agent1.py` |
| 11 | Remediation seed | Deterministic | `src/agents/agent1.py` |
| 12 | Conflicts | Deterministic | `src/documents/source_classifier.py`, `src/agents/agent1.py` |

## Notes

- Step 7 uses `NullProvider` by default; the pipeline is fully runnable without an LLM API key.
- Cached assist proposals live under `proposals/` and are never required at runtime.
- All citations pass through `src/documents/citations.py` verbatim-substring validation before persistence.
- Product profile (`product/nextboss_xt_product_profile.yaml`) and security assertions
  (`policy/security_assertions.yaml`) are content-hashed into controls draft metadata.
- Paths equal to `<TO_BE_PROVIDED>` are never invented; they are recorded as unresolved
  with `parameter_status=TO_BE_PROVIDED`.
- No environment PASS/FAIL is written into `controls.draft.json`.
"""


def write_execution_model(path: Path | None = None) -> Path:
    out = path or (PROMPTS_DIR / "agent1_execution_model.md")
    out.write_text(EXECUTION_MODEL)
    return out
