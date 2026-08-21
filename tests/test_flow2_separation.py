"""Flow 2 boundaries — separation of concerns and provider parity.

These tests make the design constraints mechanical rather than aspirational:
Flow 2 must not evaluate security assertions, must not read CRA/ETSI documents,
and must not emit a compliance verdict.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

import pytest

from src.config import (
    FORBIDDEN_VERDICT_TOKENS,
    MCP_CAPABILITY_CATALOG,
    PROJECT_ROOT,
)
from src.evidence.runner import collect_evidence
from src.mcp.providers.base import Provider
from src.mcp.providers.mock import SCENARIOS, MockProvider
from src.mcp.server import ToolRegistry
from src.registry.versioning import latest_approved_path

APPROVED_PATH = latest_approved_path()
TARGET_PATH = PROJECT_ROOT / "targets" / "nextboss-demo.mock.json"

FLOW2_PACKAGES = ("src/evidence", "src/mcp")

# Modules Flow 2 must never reach for: policy evaluation and document intelligence.
FORBIDDEN_IMPORT_PREFIXES = (
    "src.policy",
    "src.documents",
    "src.agents",
    "src.llm",
    "src.rules",
)

VERDICT_RE = re.compile(r"\b(" + "|".join(FORBIDDEN_VERDICT_TOKENS) + r")\b")


def _flow2_modules() -> list[Path]:
    modules: list[Path] = []
    for package in FLOW2_PACKAGES:
        modules.extend(sorted((PROJECT_ROOT / package).rglob("*.py")))
    return modules


def _imported_modules(path: Path) -> set[str]:
    tree = ast.parse(path.read_text())
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
    return imported


def _executable_symbols(path: Path) -> set[str]:
    """Identifiers and non-docstring literals a module actually executes.

    Comments and docstrings are excluded so that documenting *why* a boundary
    exists does not look like crossing it.
    """
    tree = ast.parse(path.read_text())
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            doc = ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)

    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node.value not in docstrings:
                symbols.add(node.value)
        elif isinstance(node, ast.Name):
            symbols.add(node.id)
        elif isinstance(node, ast.Attribute):
            symbols.add(node.attr)
    return symbols


@pytest.fixture(scope="module")
def run_result(tmp_path_factory):
    _, run = collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=tmp_path_factory.mktemp("separation"),
        run_id="RUN-TEST-SEPARATION",
        clock=lambda: "2026-08-20T12:00:00+00:00",
    )
    return run


# --- Separation of concerns ------------------------------------------------


def test_flow2_never_imports_policy_or_document_modules():
    assert _flow2_modules(), "Flow 2 packages must exist"
    offenders: list[str] = []
    for module in _flow2_modules():
        for imported in _imported_modules(module):
            if imported.startswith(FORBIDDEN_IMPORT_PREFIXES):
                offenders.append(f"{module.relative_to(PROJECT_ROOT)} imports {imported}")
    assert not offenders, "; ".join(offenders)


def test_security_assertions_are_never_loaded_by_flow2():
    for module in _flow2_modules():
        symbols = _executable_symbols(module)
        offenders = [s for s in symbols if "security_assertions" in s.lower()]
        assert not offenders, f"{module}: {offenders}"
        assert "SECURITY_ASSERTIONS_PATH" not in symbols, module


def test_flow2_does_not_read_source_documents():
    for module in _flow2_modules():
        symbols = _executable_symbols(module)
        offenders = [
            s
            for s in symbols
            if s in {"parse_pdf", "load_inventory", "build_structure_index"}
            or "documents/" in s
            or s.endswith(".pdf")
        ]
        assert not offenders, f"{module}: {offenders}"


def _iter_strings(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield str(key)
            yield from _iter_strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from _iter_strings(value)
    elif isinstance(node, str):
        yield node


def test_no_verdict_tokens_in_evidence_document(tmp_path):
    run_dir, _ = collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=tmp_path,
        run_id="RUN-TEST-VERDICT",
    )
    document = json.loads((run_dir / "evidence.json").read_text())
    offenders = [text for text in _iter_strings(document) if VERDICT_RE.search(text)]
    assert not offenders, offenders

    for artifact in (run_dir / "raw").glob("*.json"):
        payload = json.loads(artifact.read_text())
        hits = [text for text in _iter_strings(payload) if VERDICT_RE.search(text)]
        assert not hits, f"{artifact.name}: {hits}"


def test_evidence_document_carries_no_verdict_fields(run_result):
    serialized = json.dumps(run_result.model_dump(mode="json")).lower()
    for key in ("verdict", "compliance_status", "remediation", "risk_score"):
        assert f'"{key}"' not in serialized


def test_collection_errors_are_not_expressed_as_failures(run_result):
    for error in run_result.collection_errors:
        assert error.status.value != "FAIL"
        assert not VERDICT_RE.search(error.status.value)
        assert not VERDICT_RE.search(error.reason_code.value)


# --- Provider parity -------------------------------------------------------


def test_mock_scenarios_are_deterministic(tmp_path):
    signatures = []
    for index in range(2):
        _, run = collect_evidence(
            registry_path=APPROVED_PATH,
            target_path=TARGET_PATH,
            output_dir=tmp_path / f"det{index}",
            run_id="RUN-TEST-DET",
            scenario_override="partial",
            clock=lambda: "2026-08-20T12:00:00+00:00",
        )
        signatures.append([(i.evidence_id, i.raw_sha256) for i in run.evidence])
    assert signatures[0] == signatures[1]


@pytest.mark.parametrize("scenario", SCENARIOS)
def test_every_scenario_uses_the_same_normalized_schema(scenario, tmp_path):
    _, run = collect_evidence(
        registry_path=APPROVED_PATH,
        target_path=TARGET_PATH,
        output_dir=tmp_path / scenario,
        run_id=f"RUN-TEST-{scenario.upper()}",
        scenario_override=scenario,
        clock=lambda: "2026-08-20T12:00:00+00:00",
    )
    namespaces: dict[str, set[str]] = {}
    for item in run.evidence:
        if item.normalized is None:
            continue
        namespaces.setdefault(item.tool, set()).update(item.normalized)

    expected = {
        "get_tls_configuration": {"tls_configuration"},
        "get_certificates": {"certificates"},
        "get_open_ports": {"open_ports"},
        "get_file_permissions": {"file_permissions"},
        "get_services": {"services"},
        "get_users": {"local_users"},
        "get_groups": {"local_groups"},
        "get_processes": {"processes"},
        "get_firewall_rules": {"firewall_rules"},
        "get_network_configuration": {"network_configuration"},
        "get_installed_packages": {"installed_packages"},
    }
    for tool, keys in expected.items():
        assert namespaces.get(tool) == keys, tool

    # sshd_config is the only approved file path, so get_file yields both.
    assert namespaces.get("get_file") == {"file", "ssh_config"}


def test_scenarios_differ_in_facts_not_in_shape(tmp_path):
    observed = {}
    for scenario in SCENARIOS:
        registry = ToolRegistry(MockProvider("nextboss-demo", scenario))
        result = registry.call("get_tls_configuration", {"host": "h", "port": 8443})
        observed[scenario] = result.data
    assert set(observed["compliant"]) == set(observed["vulnerable"])
    assert observed["compliant"]["protocols"]["TLSv1_0"] is False
    assert observed["vulnerable"]["protocols"]["TLSv1_0"] is True


def test_provider_contract_is_provider_agnostic():
    """A second provider can only satisfy the same fourteen capabilities."""
    abstract = set(Provider.__abstractmethods__)
    assert abstract == set(MCP_CAPABILITY_CATALOG)


def test_evidence_contract_does_not_depend_on_the_provider(run_result):
    fields = set(run_result.evidence[0].model_dump().keys())
    assert "provider" in fields
    # Provider identity is recorded as metadata; it does not change the schema.
    for item in run_result.evidence:
        assert set(item.model_dump().keys()) == fields
