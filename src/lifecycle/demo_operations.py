"""Allow-listed demo remediation operations for nextboss-demo (mock only).

Each operation is a named fixture patch derived from the compliant scenario
slice for the affected resources. Callers never supply commands or free-form
paths — only a control_id that maps to a catalog entry.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "mcp" / "providers" / "fixtures"


@dataclass(frozen=True)
class DemoOperation:
    operation_id: str
    control_id: str
    proposed_change: str
    before_state: str
    expected_after_state: str
    change_reason: str
    affected_component: str
    service_restart_required: bool
    risk_and_impact: str
    validation_method: str
    rollback_method: str
    # Fixture top-level keys to replace with the compliant slice.
    compliant_sections: tuple[str, ...] = ()
    # Extra explicit patches merged after section copies (optional).
    extra_patches: dict[str, Any] = field(default_factory=dict)


@lru_cache(maxsize=1)
def _compliant_fixture() -> dict[str, Any]:
    path = FIXTURES_DIR / "compliant.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _section_patch(keys: tuple[str, ...]) -> dict[str, Any]:
    fixture = _compliant_fixture()
    return {key: copy.deepcopy(fixture[key]) for key in keys if key in fixture}


# Catalog: control_id → operation. Only these IDs may be executed on the demo target.
_DEMO_OPERATIONS: tuple[DemoOperation, ...] = (
    DemoOperation(
        operation_id="OP-DEFAULT-ACCOUNTS-SSH",
        control_id="NMS-CRA-0005",
        proposed_change=(
            "Disable vendor default accounts and harden SSH PermitRootLogin / "
            "PermitEmptyPasswords to the approved baseline."
        ),
        before_state=(
            "Default 'admin' account is usable; PermitRootLogin yes; "
            "PermitEmptyPasswords yes."
        ),
        expected_after_state=(
            "No usable default accounts; PermitRootLogin no; PermitEmptyPasswords no."
        ),
        change_reason="Close FAIL on access-control / default-credential rules.",
        affected_component="local accounts and /etc/ssh/sshd_config",
        service_restart_required=True,
        risk_and_impact=(
            "SSH may reject root and empty-password logins; operators must use "
            "named accounts. Brief SSH restart on the demo target."
        ),
        validation_method=(
            "Re-collect evidence and re-assess; require PASS for NMS-CRA-0005 "
            "on the same target and approved registry baseline."
        ),
        rollback_method="Remove this operation from the demo overlay and re-scan.",
        compliant_sections=("users", "groups", "files", "file_permissions"),
    ),
    DemoOperation(
        operation_id="OP-TLS-HARDEN",
        control_id="NMS-CRA-0006",
        proposed_change=(
            "Disable TLS 1.0/1.1 and weak ciphers; restore a valid certificate chain "
            "on management TLS endpoints."
        ),
        before_state="TLS 1.0/1.1 enabled with RC4/3DES; expired self-signed certificates.",
        expected_after_state="TLS 1.2+ only; strong ciphers; non-expired certificates.",
        change_reason="Close FAIL on cryptography / TLS configuration rules.",
        affected_component="management TLS listeners (443, 8443) and certificates",
        service_restart_required=True,
        risk_and_impact=(
            "Legacy clients that only speak TLS 1.0/1.1 will fail to connect. "
            "Demo UI/API services need a reload."
        ),
        validation_method=(
            "Re-collect evidence and re-assess; require PASS for NMS-CRA-0006 "
            "on the same target and approved registry baseline."
        ),
        rollback_method="Remove this operation from the demo overlay and re-scan.",
        compliant_sections=("tls", "certificates"),
    ),
    DemoOperation(
        operation_id="OP-SSH-FILE-PERMS",
        control_id="NMS-CRA-0007",
        proposed_change=(
            "Harden sshd_config and set non-world-writable permissions on "
            "/etc/ssh/sshd_config."
        ),
        before_state=(
            "PermitRootLogin yes; PermitEmptyPasswords yes; sshd_config mode 0666."
        ),
        expected_after_state=(
            "PermitRootLogin no; PermitEmptyPasswords no; sshd_config mode 0600."
        ),
        change_reason="Close FAIL on SSH hardening and world-writable config rules.",
        affected_component="/etc/ssh/sshd_config",
        service_restart_required=True,
        risk_and_impact="SSH restart required; root password login disabled on demo target.",
        validation_method=(
            "Re-collect evidence and re-assess; require PASS for NMS-CRA-0007 "
            "on the same target and approved registry baseline."
        ),
        rollback_method="Remove this operation from the demo overlay and re-scan.",
        compliant_sections=("files", "file_permissions"),
    ),
    DemoOperation(
        operation_id="OP-CLOSE-UNEXPECTED-PORTS",
        control_id="NMS-CRA-0011",
        proposed_change=(
            "Remove unexpected listeners (telnet, open postgres, non-baseline UI port) "
            "and align firewall/services with the management-plane baseline."
        ),
        before_state="Telnet on :23, postgres on 0.0.0.0:5432, UI on :8080.",
        expected_after_state=(
            "Only approved listeners (SSH, 443, 8443, localhost postgres)."
        ),
        change_reason="Close FAIL on unexpected open-port rules.",
        affected_component="network listeners, services, firewall",
        service_restart_required=True,
        risk_and_impact=(
            "Telnet and broad postgres exposure are removed; firewall rules tighten. "
            "Demo services that relied on :8080 must use :8443."
        ),
        validation_method=(
            "Re-collect evidence and re-assess; require PASS for NMS-CRA-0011 "
            "on the same target and approved registry baseline."
        ),
        rollback_method="Remove this operation from the demo overlay and re-scan.",
        compliant_sections=(
            "listeners",
            "services",
            "processes",
            "firewall",
            "network_configuration",
            "packages",
        ),
    ),
)

OPERATIONS_BY_CONTROL: dict[str, DemoOperation] = {
    op.control_id: op for op in _DEMO_OPERATIONS
}
OPERATIONS_BY_ID: dict[str, DemoOperation] = {
    op.operation_id: op for op in _DEMO_OPERATIONS
}


def get_operation_for_control(control_id: str) -> DemoOperation | None:
    return OPERATIONS_BY_CONTROL.get(control_id)


def get_operation(operation_id: str) -> DemoOperation | None:
    return OPERATIONS_BY_ID.get(operation_id)


def patches_for_operation(operation: DemoOperation) -> dict[str, Any]:
    patches = _section_patch(operation.compliant_sections)
    if operation.extra_patches:
        for key, value in operation.extra_patches.items():
            patches[key] = copy.deepcopy(value)
    return patches
