"""Deterministic security-area coverage matrix for Agent 1 enrichment."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.config import TO_BE_PROVIDED
from src.policy.assertions import SecurityAssertions
from src.product.profile import ProductProfile, is_resolved


HOST_COMPONENT = "Host"


@dataclass(frozen=True)
class EvidenceSpec:
    evidence_key: str
    mcp_tool: str
    description: str
    # Parameter strategy:
    # - "ports_from_components": one item per selected component port
    # - "path_from_profile_key": use profile.configuration.<key>
    # - "none": empty parameters
    param_mode: str = "none"
    profile_path_key: str | None = None


@dataclass(frozen=True)
class AreaSpec:
    area_id: str
    name: str
    cra_points: tuple[str, ...]
    component_names: tuple[str, ...]  # empty => Host
    evidence_specs: tuple[EvidenceSpec, ...]
    assertion_refs: tuple[str, ...]
    emit_rules: bool = False


AREA_MATRIX: tuple[AreaSpec, ...] = (
    AreaSpec(
        area_id="A",
        name="TLS / certificates",
        cra_points=("I-2-b", "I-2-e"),
        component_names=("Management UI", "REST API"),
        evidence_specs=(
            EvidenceSpec(
                "tls_configuration",
                "get_tls_configuration",
                "TLS protocol and cipher configuration for management interfaces",
                "ports_from_components",
            ),
            EvidenceSpec(
                "certificates",
                "get_certificates",
                "Certificate configuration and validity",
                "ports_from_components",
            ),
            EvidenceSpec(
                "open_ports",
                "get_open_ports",
                "Listener information for TLS endpoints",
                "ports_from_components",
            ),
        ),
        assertion_refs=(
            "tls.disallowed_protocols",
            "tls.disallowed_cipher_patterns",
            "tls.certificate.must_not_be_expired",
        ),
        emit_rules=True,
    ),
    AreaSpec(
        area_id="B",
        name="Network exposure",
        cra_points=("I-2-b", "I-2-j"),
        component_names=(
            "Management UI",
            "REST API",
            "PostgreSQL",
            "SSH Administration",
        ),
        evidence_specs=(
            EvidenceSpec(
                "open_ports",
                "get_open_ports",
                "Open ports, bind addresses, and owning services",
                "none",
            ),
            EvidenceSpec(
                "network_configuration",
                "get_network_configuration",
                "Network interfaces and bind configuration",
                "none",
            ),
            EvidenceSpec(
                "firewall_rules",
                "get_firewall_rules",
                "Firewall rules affecting exposed listeners",
                "none",
            ),
            EvidenceSpec(
                "services",
                "get_services",
                "Services owning network listeners",
                "none",
            ),
        ),
        assertion_refs=(
            "network.expected_ports",
            "network.unexpected_listener_action",
        ),
        emit_rules=True,
    ),
    AreaSpec(
        area_id="C",
        name="SSH",
        cra_points=("I-2-d", "I-2-f"),
        component_names=("SSH Administration",),
        evidence_specs=(
            EvidenceSpec(
                "ssh_listener",
                "get_open_ports",
                "SSH listener on administration port",
                "ports_from_components",
            ),
            EvidenceSpec(
                "ssh_service",
                "get_services",
                "SSH service state",
                "none",
            ),
            EvidenceSpec(
                "ssh_config",
                "get_file",
                "SSH daemon configuration",
                "path_from_profile_key",
                "ssh_config_file",
            ),
            EvidenceSpec(
                "ssh_config_permissions",
                "get_file_permissions",
                "Permissions on SSH configuration file",
                "path_from_profile_key",
                "ssh_config_file",
            ),
        ),
        assertion_refs=(
            "ssh.SSH-ROOT-LOGIN",
            "ssh.SSH-EMPTY-PASSWORDS",
        ),
        emit_rules=True,
    ),
    AreaSpec(
        area_id="D",
        name="PostgreSQL",
        cra_points=("I-2-d", "I-2-j"),
        component_names=("PostgreSQL",),
        evidence_specs=(
            EvidenceSpec(
                "postgres_listener",
                "get_open_ports",
                "PostgreSQL listener and bind address",
                "ports_from_components",
            ),
            EvidenceSpec(
                "postgres_service",
                "get_services",
                "PostgreSQL service state",
                "none",
            ),
            EvidenceSpec(
                "postgres_network",
                "get_network_configuration",
                "Network configuration relevant to database exposure",
                "none",
            ),
            EvidenceSpec(
                "postgres_firewall",
                "get_firewall_rules",
                "Firewall rules protecting PostgreSQL",
                "none",
            ),
            EvidenceSpec(
                "postgres_config",
                "get_file",
                "PostgreSQL configuration when path is supplied",
                "path_from_profile_key",
                "postgres_config_file",
            ),
        ),
        assertion_refs=("postgresql.POSTGRES-NOT-PUBLIC",),
        emit_rules=False,
    ),
    AreaSpec(
        area_id="E",
        name="Local accounts / LDAP",
        cra_points=("I-2-d",),
        component_names=(),
        evidence_specs=(
            EvidenceSpec(
                "local_users",
                "get_users",
                "Local and privileged user accounts",
                "none",
            ),
            EvidenceSpec(
                "local_groups",
                "get_groups",
                "Group membership for privileged access",
                "none",
            ),
            EvidenceSpec(
                "auth_config",
                "get_file",
                "Authentication configuration evidence when path is supplied",
                "path_from_profile_key",
                "application_config",
            ),
            EvidenceSpec(
                "auth_config_permissions",
                "get_file_permissions",
                "Permissions on authentication-related configuration",
                "path_from_profile_key",
                "application_config",
            ),
        ),
        assertion_refs=(
            "authentication.AUTH-LOCAL-USERS",
            "authentication.AUTH-LDAP",
        ),
        emit_rules=False,
    ),
    AreaSpec(
        area_id="F",
        name="RBAC / authorization",
        cra_points=("I-2-d",),
        component_names=(),
        evidence_specs=(
            EvidenceSpec(
                "privileged_groups",
                "get_groups",
                "Privileged group membership",
                "none",
            ),
            EvidenceSpec(
                "rbac_users",
                "get_users",
                "User accounts relevant to authorization",
                "none",
            ),
            EvidenceSpec(
                "rbac_config",
                "get_file",
                "Application RBAC configuration when path is supplied",
                "path_from_profile_key",
                "application_config",
            ),
        ),
        assertion_refs=("authorization.AUTHZ-PRIVILEGED-GROUPS",),
        emit_rules=False,
    ),
    AreaSpec(
        area_id="G",
        name="File permissions",
        cra_points=("I-2-f",),
        component_names=("SSH Administration",),
        evidence_specs=(
            EvidenceSpec(
                "file_permissions",
                "get_file_permissions",
                "Ownership and permissions on security-sensitive configuration files",
                "path_from_profile_key",
                "ssh_config_file",
            ),
            EvidenceSpec(
                "tls_config_permissions",
                "get_file_permissions",
                "Permissions on TLS configuration when path is supplied",
                "path_from_profile_key",
                "tls_config_file",
            ),
            EvidenceSpec(
                "app_config_permissions",
                "get_file_permissions",
                "Permissions on application configuration when path is supplied",
                "path_from_profile_key",
                "application_config",
            ),
            EvidenceSpec(
                "postgres_config_permissions",
                "get_file_permissions",
                "Permissions on PostgreSQL configuration when path is supplied",
                "path_from_profile_key",
                "postgres_config_file",
            ),
        ),
        assertion_refs=("files.FILE-CONFIG-PERMISSIONS",),
        emit_rules=True,
    ),
    AreaSpec(
        area_id="H",
        name="Firewall",
        cra_points=("I-2-h", "I-2-j"),
        component_names=(),
        evidence_specs=(
            EvidenceSpec(
                "firewall_rules",
                "get_firewall_rules",
                "Firewall state and rules for management and database interfaces",
                "none",
            ),
        ),
        assertion_refs=("firewall.FIREWALL-STATE",),
        emit_rules=False,
    ),
    AreaSpec(
        area_id="I",
        name="Services",
        cra_points=("I-2-h", "I-2-j"),
        component_names=(),
        evidence_specs=(
            EvidenceSpec(
                "services",
                "get_services",
                "Running and enabled services",
                "none",
            ),
            EvidenceSpec(
                "open_ports",
                "get_open_ports",
                "Services owning exposed ports",
                "none",
            ),
        ),
        assertion_refs=("services.SERVICE-INVENTORY",),
        emit_rules=False,
    ),
    AreaSpec(
        area_id="J",
        name="Packages",
        cra_points=("II-1",),
        component_names=(),
        evidence_specs=(
            EvidenceSpec(
                "installed_packages",
                "get_installed_packages",
                "Package and version inventory",
                "none",
            ),
        ),
        assertion_refs=("packages.PACKAGE-INVENTORY",),
        emit_rules=False,
    ),
    AreaSpec(
        area_id="K",
        name="Security logging",
        cra_points=("I-2-l",),
        component_names=(),
        evidence_specs=(
            EvidenceSpec(
                "security_logs",
                "get_security_logs",
                "Security and audit logging availability",
                "none",
            ),
        ),
        assertion_refs=("logging.SECURITY-LOGGING",),
        emit_rules=False,
    ),
)


def areas_for_point(key: str) -> list[AreaSpec]:
    return [area for area in AREA_MATRIX if key in area.cra_points]


def _protocol_path_token(protocol: str) -> str:
    """Map TLS protocol labels to evidence-namespace path tokens."""
    token = protocol.replace(".", "_").replace("-", "_")
    if token.startswith("TLS") and not token.startswith("TLSv"):
        token = token.replace("TLS", "TLSv", 1)
    return token


def rules_for_area(area: AreaSpec, policy: SecurityAssertions) -> list[dict[str, Any]]:
    """Build deterministic rule-DSL fragments from the loaded assertions YAML."""
    if not area.emit_rules:
        return []

    rules: list[dict[str, Any]] = []

    if area.area_id == "A":
        conditions: list[dict[str, Any]] = []
        for proto in policy.tls.disallowed_protocols:
            conditions.append(
                {
                    "path": f"tls_configuration.protocols.{_protocol_path_token(proto)}",
                    "operator": "EQ",
                    "value": False,
                }
            )
        for pattern in policy.tls.disallowed_cipher_patterns:
            conditions.append(
                {
                    "path": "tls_configuration.cipher_suites",
                    "operator": "NOT_CONTAINS",
                    "value": pattern,
                }
            )
        if policy.tls.certificate.must_not_be_expired:
            conditions.append(
                {
                    "path": "certificates.expired",
                    "operator": "EQ",
                    "value": False,
                }
            )
        if conditions:
            rules.append({"all": conditions})

    elif area.area_id == "B":
        rules.append(
            {
                "all": [
                    {
                        "path": "open_ports.unexpected_listeners",
                        "operator": "EQ",
                        "value": [],
                    }
                ]
            }
        )

    elif area.area_id == "C":
        conditions = []
        for assertion in policy.ssh.assertions:
            if assertion.key and assertion.allowed is not None:
                conditions.append(
                    {
                        "path": f"ssh_config.{assertion.key}",
                        "operator": "IN",
                        "value": list(assertion.allowed),
                    }
                )
        if conditions:
            rules.append({"all": conditions})

    elif area.area_id == "G":
        file_assertion = policy.files.by_id("FILE-CONFIG-PERMISSIONS")
        if file_assertion and file_assertion.disallow_world_writable:
            rules.append(
                {
                    "all": [
                        {
                            "path": "file_permissions.world_writable",
                            "operator": "EQ",
                            "value": False,
                        }
                    ]
                }
            )

    return rules


def rules_for_point(key: str, policy: SecurityAssertions) -> list[dict[str, Any]]:
    """Collect YAML-derived rules for all areas covering a CRA point."""
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for area in areas_for_point(key):
        for rule in rules_for_area(area, policy):
            # Deterministic de-dupe by canonical key
            marker = repr(rule)
            if marker not in seen:
                seen.add(marker)
                merged.append(rule)
    return merged


def assertion_refs_for_point(key: str) -> list[str]:
    refs: list[str] = []
    seen: set[str] = set()
    for area in areas_for_point(key):
        for ref in area.assertion_refs:
            if ref not in seen:
                seen.add(ref)
                refs.append(ref)
    return refs


@dataclass
class BuiltEvidenceItem:
    evidence_key: str
    mcp_tool: str
    description: str
    parameters: dict[str, Any] = field(default_factory=dict)
    parameter_status: str = "RESOLVED"
    unresolved_reason: str | None = None


def _path_from_profile(profile: ProductProfile, key: str) -> str:
    return getattr(profile.configuration, key)


def build_evidence_items_for_point(
    key: str,
    profile: ProductProfile,
) -> list[BuiltEvidenceItem]:
    """Expand area evidence specs into concrete evidence items for a CRA point."""
    items: list[BuiltEvidenceItem] = []
    seen_keys: set[str] = set()

    for area in areas_for_point(key):
        component_ifaces = [
            profile.interface_by_name(name)
            for name in area.component_names
            if profile.interface_by_name(name) is not None
        ]

        for spec in area.evidence_specs:
            if spec.param_mode == "ports_from_components":
                for iface in component_ifaces:
                    assert iface is not None
                    ev_key = f"{spec.evidence_key}_{iface.port}"
                    if ev_key in seen_keys:
                        continue
                    seen_keys.add(ev_key)
                    items.append(
                        BuiltEvidenceItem(
                            evidence_key=ev_key,
                            mcp_tool=spec.mcp_tool,
                            description=f"{spec.description} ({iface.name}:{iface.port})",
                            parameters={"port": iface.port},
                            parameter_status="RESOLVED",
                        )
                    )
            elif spec.param_mode == "path_from_profile_key":
                assert spec.profile_path_key is not None
                path_value = _path_from_profile(profile, spec.profile_path_key)
                if spec.evidence_key in seen_keys:
                    continue
                seen_keys.add(spec.evidence_key)
                if is_resolved(path_value):
                    items.append(
                        BuiltEvidenceItem(
                            evidence_key=spec.evidence_key,
                            mcp_tool=spec.mcp_tool,
                            description=spec.description,
                            parameters={"path": path_value},
                            parameter_status="RESOLVED",
                        )
                    )
                else:
                    items.append(
                        BuiltEvidenceItem(
                            evidence_key=spec.evidence_key,
                            mcp_tool=spec.mcp_tool,
                            description=spec.description,
                            parameters={"path": TO_BE_PROVIDED},
                            parameter_status="TO_BE_PROVIDED",
                            unresolved_reason=(
                                f"Config path {spec.profile_path_key} is "
                                f"{TO_BE_PROVIDED}; do not invent a value"
                            ),
                        )
                    )
            else:
                if spec.evidence_key in seen_keys:
                    continue
                seen_keys.add(spec.evidence_key)
                items.append(
                    BuiltEvidenceItem(
                        evidence_key=spec.evidence_key,
                        mcp_tool=spec.mcp_tool,
                        description=spec.description,
                        parameters={},
                        parameter_status="RESOLVED",
                    )
                )

    return items


def component_names_for_point(key: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    host_needed = False
    for area in areas_for_point(key):
        if not area.component_names:
            host_needed = True
            continue
        for name in area.component_names:
            if name not in seen:
                seen.add(name)
                names.append(name)
    if host_needed and HOST_COMPONENT not in seen:
        names.append(HOST_COMPONENT)
    return names
