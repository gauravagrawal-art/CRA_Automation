"""Runtime target profile — where a scan runs.

This is deliberately distinct from the product profile used by Agent 1. The
product profile describes what NextBoss-XT *is* (ports, interfaces, config
paths); the target profile describes *where* this particular scan runs. Product
facts already carried by an approved control are not duplicated here.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field, field_validator

from src.config import TARGETS_DIR

SUPPORTED_PROVIDERS = ("mock", "ssh")
MOCK_SCENARIOS = ("compliant", "partial", "vulnerable")

# Keys that would represent inline credential material. Only *references* to a
# secret are permitted in a target profile.
_FORBIDDEN_SECRET_KEYS = re.compile(
    r"(?i)^(password|passwd|passphrase|private_key|private_key_data|key_data|"
    r"secret|token|api_key|credential|credentials)$"
)


class SSHTarget(BaseModel):
    host: str
    port: int = 22
    username: str
    credential_ref: str
    known_hosts_ref: str | None = None

    model_config = {"extra": "forbid"}


class Endpoint(BaseModel):
    host: str

    model_config = {"extra": "forbid"}


class TargetProfile(BaseModel):
    target_id: str
    provider: str
    host: str
    environment: str = "compliant"
    endpoints: dict[str, Endpoint] = Field(default_factory=dict)
    ssh: SSHTarget | None = None

    model_config = {"extra": "forbid"}

    @field_validator("provider")
    @classmethod
    def _known_provider(cls, value: str) -> str:
        if value not in SUPPORTED_PROVIDERS:
            raise ValueError(
                f"Unsupported provider '{value}'. Supported: {', '.join(SUPPORTED_PROVIDERS)}"
            )
        return value

    def endpoint_host(self, endpoint_ref: str | None) -> str:
        """Resolve a symbolic endpoint reference to a host.

        Falls back to the target host when the profile declares no specific
        endpoint address.
        """
        if endpoint_ref and endpoint_ref in self.endpoints:
            return self.endpoints[endpoint_ref].host
        return self.host


def assert_no_inline_secrets(data: object, path: str = "") -> None:
    """Raise if the profile carries credential material rather than a reference."""
    if isinstance(data, dict):
        for key, value in data.items():
            location = f"{path}.{key}" if path else key
            if _FORBIDDEN_SECRET_KEYS.match(str(key)):
                raise ValueError(
                    f"Target profile must not contain inline secret material at '{location}'. "
                    "Use 'credential_ref' to name an environment/secret reference instead."
                )
            assert_no_inline_secrets(value, location)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            assert_no_inline_secrets(value, f"{path}[{index}]")
    elif isinstance(data, str) and "PRIVATE KEY-----" in data:
        location = path or "<root>"
        raise ValueError(
            f"Target profile must not contain inline key material at '{location}'."
        )


def load_target_profile(path: Path | None = None) -> tuple[TargetProfile, str]:
    """Load and validate a target profile; return (model, sha256 of raw bytes)."""
    profile_path = path or (TARGETS_DIR / "nextboss-demo.mock.json")
    if not profile_path.exists():
        raise FileNotFoundError(f"Target profile not found: {profile_path}")

    raw = profile_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    data = json.loads(raw.decode("utf-8"))

    assert_no_inline_secrets(data)
    profile = TargetProfile.model_validate(data)

    if profile.provider == "mock" and profile.environment not in MOCK_SCENARIOS:
        raise ValueError(
            f"Unknown mock scenario '{profile.environment}'. "
            f"Expected one of: {', '.join(MOCK_SCENARIOS)}"
        )
    return profile, sha256
