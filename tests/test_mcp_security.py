"""Infrastructure MCP — argument validation, allowlists, limits and redaction."""

from __future__ import annotations

import inspect
import json

import pytest

from src.config import (
    MCP_CAPABILITY_CATALOG,
    REDACTION_PLACEHOLDER,
    TO_BE_PROVIDED,
)
from src.mcp import policy
from src.mcp.contracts import TOOL_ARGUMENT_SCHEMAS, is_registered_tool
from src.mcp.errors import (
    InvalidArgumentsError,
    OutputLimitExceededError,
    PathNotAllowedError,
    RedactionFailedError,
    SourceUnavailableError,
    ToolNotRegisteredError,
)
from src.mcp.providers.base import Provider
from src.mcp.providers.mock import MockProvider
from src.mcp.redaction import contains_secret_material, redact
from src.mcp.server import ToolRegistry

# Compared against whole underscore-separated tokens, so a read capability
# such as `get_installed_packages` is not confused with `install`.
MUTATION_VERBS = {
    "set",
    "write",
    "delete",
    "remove",
    "create",
    "update",
    "install",
    "uninstall",
    "restart",
    "stop",
    "start",
    "exec",
    "run",
    "shell",
    "command",
    "modify",
    "patch",
    "put",
    "post",
}


@pytest.fixture
def registry() -> ToolRegistry:
    return ToolRegistry(MockProvider("nextboss-demo", "vulnerable"))


# --- Registration ----------------------------------------------------------


def test_only_catalog_capabilities_are_registered():
    assert set(TOOL_ARGUMENT_SCHEMAS) == set(MCP_CAPABILITY_CATALOG)
    assert not is_registered_tool("get_everything")
    assert not is_registered_tool("run_command")


def test_unregistered_tool_is_rejected(registry):
    with pytest.raises(ToolNotRegisteredError):
        registry.call("run_command", {"cmd": "cat /etc/shadow"})


def test_no_capability_accepts_a_command_string():
    for tool, schema in TOOL_ARGUMENT_SCHEMAS.items():
        fields = set(schema.model_fields)
        assert not fields & {"command", "cmd", "shell", "script", "query", "exec"}, tool


# --- Argument validation ---------------------------------------------------


def test_malformed_arguments_are_rejected(registry):
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_file", {"path": "/etc/ssh/sshd_config", "sudo": True})
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_file", {})
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_file", {"path": ""})
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_open_ports", {"port": 70000})
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_tls_configuration", {"host": "h"})


def test_argument_validation_happens_before_the_provider(registry, monkeypatch):
    called = []
    monkeypatch.setattr(
        registry.provider,
        "get_file",
        lambda **kwargs: called.append(kwargs) or {},
    )
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_file", {"path": "/etc/ssh/sshd_config", "unexpected": 1})
    assert called == []


# --- Path allowlist --------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "/etc/shadow",
        "/etc/passwd",
        "/root/.ssh/id_rsa",
        "etc/ssh/sshd_config",
        "/etc/ssh/../shadow",
        "/etc/ssh/sshd_config\x00/etc/shadow",
        TO_BE_PROVIDED,
    ],
)
def test_path_allowlist_refuses_disallowed_paths(registry, path):
    with pytest.raises(PathNotAllowedError):
        registry.call("get_file", {"path": path})


def test_path_allowlist_permits_an_approved_path(registry):
    result = registry.call("get_file", {"path": "/etc/ssh/sshd_config"})
    assert result.data["path"] == "/etc/ssh/sshd_config"


def test_path_policy_applies_to_permissions_tool_too(registry):
    with pytest.raises(PathNotAllowedError):
        registry.call("get_file_permissions", {"path": "/etc/shadow"})


# --- Output limits ---------------------------------------------------------


def test_output_size_limit_is_enforced(registry, monkeypatch):
    monkeypatch.setattr(policy, "MCP_MAX_OUTPUT_BYTES", 32)
    with pytest.raises(OutputLimitExceededError):
        registry.call("get_installed_packages")


def test_file_size_limit_is_enforced(registry, monkeypatch):
    monkeypatch.setattr(policy, "MCP_MAX_FILE_BYTES", 8)
    with pytest.raises(OutputLimitExceededError):
        registry.call("get_file", {"path": "/etc/ssh/sshd_config"})


def test_log_bounds_are_enforced(registry):
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_security_logs", {"max_entries": 100000})
    with pytest.raises(InvalidArgumentsError):
        registry.call("get_security_logs", {"time_range_hours": 100000})


def test_log_results_stay_within_the_requested_bound():
    registry = ToolRegistry(MockProvider("nextboss-demo", "compliant"))
    result = registry.call("get_security_logs", {"max_entries": 2})
    assert result.data["returned_entries"] == 2
    assert result.data["truncated"] is True
    assert len(result.data["entries"]) == 2


def test_missing_log_source_is_reported_not_invented():
    registry = ToolRegistry(MockProvider("nextboss-demo", "partial"))
    with pytest.raises(SourceUnavailableError):
        registry.call("get_security_logs")


# --- Redaction -------------------------------------------------------------


def test_password_hashes_and_tokens_are_redacted(registry):
    result = registry.call("get_users")
    serialized = json.dumps(result.data)
    assert "SYNTHETIC" not in serialized
    assert "ghp_" not in serialized
    assert REDACTION_PLACEHOLDER in serialized
    for user in result.data["users"]:
        assert user["password_hash"] == REDACTION_PLACEHOLDER
    assert not contains_secret_material(result.data)


def test_redaction_masks_key_material_in_free_text():
    payload = {
        "content": (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        ),
        "note": "AKIAIOSFODNN7EXAMPLE",
    }
    sanitized = redact(payload)
    assert "PRIVATE KEY" not in sanitized["content"]
    assert sanitized["note"] == REDACTION_PLACEHOLDER


def test_redaction_preserves_non_secret_security_evidence(registry):
    result = registry.call("get_file", {"path": "/etc/ssh/sshd_config"})
    content = result.data["content"]
    assert "PermitRootLogin yes" in content
    assert "PermitEmptyPasswords yes" in content


def test_redaction_fails_closed_on_uninspectable_values():
    class Opaque:
        pass

    with pytest.raises(RedactionFailedError):
        redact({"data": Opaque()})


def test_redaction_fails_closed_on_excessive_nesting():
    payload: dict = {}
    cursor = payload
    for _ in range(200):
        cursor["next"] = {}
        cursor = cursor["next"]
    with pytest.raises(RedactionFailedError):
        redact(payload)


# --- Read-only guarantee ---------------------------------------------------


def test_provider_interface_exposes_no_write_capability():
    methods = [
        name
        for name, _ in inspect.getmembers(Provider, predicate=inspect.isfunction)
        if not name.startswith("__") and name != "close"
    ]
    assert methods, "the provider interface must declare capabilities"
    for name in methods:
        assert name.startswith("get_"), f"non-read capability on Provider: {name}"
        assert not set(name.split("_")) & MUTATION_VERBS, name


def test_mock_provider_implements_every_capability():
    provider = MockProvider("nextboss-demo", "compliant")
    for tool in MCP_CAPABILITY_CATALOG:
        assert callable(getattr(provider, tool))


# --- Untrusted target content ---------------------------------------------


def test_prompt_injection_in_target_output_remains_data(registry):
    services = registry.call("get_services").data["services"]
    injected = [s for s in services if "Ignore previous instructions" in (s["description"] or "")]
    assert injected, "the vulnerable fixture should carry an injection string"

    file_result = registry.call("get_file", {"path": "/etc/ssh/sshd_config"})
    assert "Ignore previous instructions" in file_result.data["content"]

    # It is carried as evidence and nothing more: no verdict, no instruction
    # channel, and the envelope still reports a plain collection status.
    assert file_result.collection_status == "COLLECTED"
    assert "verdict" not in json.dumps(file_result.model_dump()).lower()


def test_every_result_carries_provenance(registry):
    result = registry.call("get_system_info")
    assert result.tool == "get_system_info"
    assert result.target_id == "nextboss-demo"
    assert result.provider == "mock"
    assert result.collected_at
    assert result.collection_status == "COLLECTED"
