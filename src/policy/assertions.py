"""Security assertions policy loading and reference resolution."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from src.config import SECURITY_ASSERTIONS_PATH


class AssertionsMetadata(BaseModel):
    name: str
    version: str
    source_type: str


class TlsCertificateAssertion(BaseModel):
    must_not_be_expired: bool = True


class TlsAssertions(BaseModel):
    disallowed_protocols: list[str] = Field(default_factory=list)
    disallowed_cipher_patterns: list[str] = Field(default_factory=list)
    certificate: TlsCertificateAssertion = Field(default_factory=TlsCertificateAssertion)


class NetworkAssertions(BaseModel):
    expected_ports: list[int] = Field(default_factory=list)
    unexpected_listener_action: str = "REVIEW"


class NamedAssertion(BaseModel):
    id: str
    description: str | None = None
    key: str | None = None
    allowed: list[str] | None = None
    disallow_world_writable: bool | None = None
    required: bool | None = None


class AssertionSection(BaseModel):
    assertions: list[NamedAssertion] = Field(default_factory=list)

    def by_id(self, assertion_id: str) -> NamedAssertion | None:
        for item in self.assertions:
            if item.id == assertion_id:
                return item
        return None


class SecurityAssertions(BaseModel):
    metadata: AssertionsMetadata
    tls: TlsAssertions = Field(default_factory=TlsAssertions)
    network: NetworkAssertions = Field(default_factory=NetworkAssertions)
    ssh: AssertionSection = Field(default_factory=AssertionSection)
    postgresql: AssertionSection = Field(default_factory=AssertionSection)
    authentication: AssertionSection = Field(default_factory=AssertionSection)
    authorization: AssertionSection = Field(default_factory=AssertionSection)
    files: AssertionSection = Field(default_factory=AssertionSection)
    firewall: AssertionSection = Field(default_factory=AssertionSection)
    services: AssertionSection = Field(default_factory=AssertionSection)
    packages: AssertionSection = Field(default_factory=AssertionSection)
    logging: AssertionSection = Field(default_factory=AssertionSection)

    def raw_section(self, name: str) -> Any:
        return getattr(self, name, None)


def load_security_assertions(
    path: Path | None = None,
) -> tuple[SecurityAssertions, str]:
    """Load and validate security assertions; return (model, sha256 of raw bytes)."""
    assertions_path = path or SECURITY_ASSERTIONS_PATH
    if not assertions_path.exists():
        raise FileNotFoundError(f"Security assertions not found: {assertions_path}")
    raw = assertions_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    data = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Security assertions must be a mapping: {assertions_path}")
    return SecurityAssertions.model_validate(data), sha256


def resolve_assertion_ref(policy: SecurityAssertions, ref: str) -> Any:
    """Resolve an assertion reference.

    Supports:
    - dotted paths: ``tls.disallowed_protocols``, ``tls.certificate.must_not_be_expired``
    - section-plus-id: ``ssh.SSH-ROOT-LOGIN``, ``postgresql.POSTGRES-NOT-PUBLIC``
    """
    if not ref or "." not in ref:
        raise KeyError(f"Invalid assertion ref: {ref!r}")

    section_name, remainder = ref.split(".", 1)
    section = policy.raw_section(section_name)
    if section is None:
        raise KeyError(f"Unknown assertion section in ref: {ref!r}")

    # Named assertion id form: section.ASSERTION-ID
    if isinstance(section, AssertionSection):
        named = section.by_id(remainder)
        if named is not None:
            return named
        # Allow dotted paths under a section that also has assertions (rare)
        # Fall through to attribute walk for nested fields if present.

    # Dotted attribute path under the section model
    current: Any = section
    for part in remainder.split("."):
        if isinstance(current, BaseModel):
            if not hasattr(current, part):
                raise KeyError(f"Unresolved assertion ref: {ref!r}")
            current = getattr(current, part)
        elif isinstance(current, dict):
            if part not in current:
                raise KeyError(f"Unresolved assertion ref: {ref!r}")
            current = current[part]
        else:
            raise KeyError(f"Unresolved assertion ref: {ref!r}")
    return current
