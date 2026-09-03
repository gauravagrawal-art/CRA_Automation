"""Explicit control-to-asset applicability for the compliance view.

Controls do not automatically apply to every discovered asset. Mapping is
rule-based and auditable so a future LLM can suggest, but not invent,
applicability.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from src.compliance.models import Asset, AssetType

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
ASSETS_PATH = FIXTURES_DIR / "assets.json"

# Asset-type groups used by applicability rules.
SERVER_LIKE = {
    AssetType.APPLICATION_SERVER,
    AssetType.WEB_SERVER,
    AssetType.DATABASE,
    AssetType.VM,
    AssetType.GATEWAY,
}
NETWORK_DEVICES = {
    AssetType.ROUTER,
    AssetType.SWITCH,
    AssetType.FIREWALL,
    AssetType.LOAD_BALANCER,
    AssetType.NETWORK_APPLIANCE,
    AssetType.GATEWAY,
}
SSH_CAPABLE = SERVER_LIKE | {
    AssetType.ROUTER,
    AssetType.SWITCH,
    AssetType.FIREWALL,
    AssetType.NETWORK_APPLIANCE,
}
HTTPS_MGMT = {
    AssetType.APPLICATION_SERVER,
    AssetType.WEB_SERVER,
    AssetType.VM,
    AssetType.SWITCH,
    AssetType.ROUTER,
    AssetType.FIREWALL,
    AssetType.LOAD_BALANCER,
    AssetType.GATEWAY,
    AssetType.NETWORK_APPLIANCE,
}
OS_ASSETS = {
    AssetType.APPLICATION_SERVER,
    AssetType.WEB_SERVER,
    AssetType.DATABASE,
    AssetType.VM,
    AssetType.GATEWAY,
}
AUTH_ASSETS = {
    AssetType.APPLICATION_SERVER,
    AssetType.WEB_SERVER,
    AssetType.VM,
    AssetType.ROUTER,
    AssetType.SWITCH,
    AssetType.FIREWALL,
    AssetType.LOAD_BALANCER,
    AssetType.GATEWAY,
    AssetType.NETWORK_APPLIANCE,
}

# Keyword → preferred asset-type set (first match wins for category).
_RULES: list[tuple[re.Pattern[str], set[AssetType]]] = [
    (re.compile(r"\b(tls|https|certificate|cipher|x\.?509)\b", re.I), HTTPS_MGMT),
    (re.compile(r"\b(ssh|sshd|permitrootlogin|empty.?password)\b", re.I), SSH_CAPABLE),
    (re.compile(r"\b(postgres|database|sql|pg_hba|5432)\b", re.I), {AssetType.DATABASE}),
    (re.compile(r"\b(firewall|iptables|firewalld|packet.?filter)\b", re.I), {
        AssetType.FIREWALL,
        AssetType.APPLICATION_SERVER,
        AssetType.VM,
    }),
    (re.compile(r"\b(authentication|password|account|user|login|ldap|credential)\b", re.I), AUTH_ASSETS),
    (re.compile(r"\b(operating.?system|kernel|package|patch|rhel|linux|os\b)\b", re.I), OS_ASSETS),
    (re.compile(r"\b(router|switch|snmp|network.?management|nms|oss)\b", re.I), NETWORK_DEVICES),
    (re.compile(r"\b(container|docker|sidecar)\b", re.I), {AssetType.CONTAINER}),
    (re.compile(r"\b(load.?balancer|vip)\b", re.I), {AssetType.LOAD_BALANCER}),
]


def _haystack(control: dict) -> str:
    parts = [
        str(control.get("control_id") or ""),
        str(control.get("title") or ""),
        str(control.get("technical_control") or ""),
        str(control.get("nms_interpretation") or ""),
    ]
    legal = control.get("legal_requirement") or {}
    if isinstance(legal, dict):
        parts.append(str(legal.get("normalized_requirement") or ""))
    assertions = control.get("assertion_refs") or []
    parts.extend(str(a) for a in assertions)
    for item in control.get("evidence_plan") or []:
        if isinstance(item, dict):
            parts.append(str(item.get("evidence_key") or ""))
            parts.append(str(item.get("mcp_tool") or ""))
            parts.append(str(item.get("description") or ""))
    return " ".join(parts)


def applicable_asset_types(control: dict) -> set[AssetType]:
    """Return asset types this control applies to."""
    text = _haystack(control)
    for pattern, types in _RULES:
        if pattern.search(text):
            return set(types)
    # Default: application / host-level NMS assets, not every network device.
    return {
        AssetType.APPLICATION_SERVER,
        AssetType.WEB_SERVER,
        AssetType.VM,
        AssetType.GATEWAY,
    }


def applicable_assets(control: dict, assets: list[Asset]) -> list[Asset]:
    """Filter inventory to assets this control applies to."""
    types = applicable_asset_types(control)
    matched = [a for a in assets if a.type in types]
    if matched:
        return matched
    # Fallback: keep at least the primary application server if present.
    for asset in assets:
        if asset.type is AssetType.APPLICATION_SERVER:
            return [asset]
    return assets[:1] if assets else []


def primary_asset(control: dict, assets: list[Asset], *, status_is_fail: bool = False) -> Asset | None:
    """Pick the best single asset to attribute a finding or remediation to.

    Prefer the most specific match (DATABASE for DB controls, SWITCH/ROUTER for
    network TLS, APPLICATION_SERVER otherwise). Does not clone findings onto
    every applicable device.
    """
    candidates = applicable_assets(control, assets)
    if not candidates:
        return None

    text = _haystack(control).lower()
    preference: list[AssetType] = []
    if re.search(r"\b(postgres|database|sql|5432)\b", text):
        preference = [AssetType.DATABASE]
    elif re.search(r"\b(tls|https|certificate)\b", text) and re.search(
        r"\b(switch|router|management.?interface|network)\b", text
    ):
        preference = [AssetType.SWITCH, AssetType.ROUTER, AssetType.FIREWALL]
    elif re.search(r"\b(tls|https|certificate)\b", text):
        preference = [
            AssetType.APPLICATION_SERVER,
            AssetType.WEB_SERVER,
            AssetType.LOAD_BALANCER,
            AssetType.SWITCH,
        ]
    elif re.search(r"\bssh\b", text):
        preference = [
            AssetType.APPLICATION_SERVER,
            AssetType.ROUTER,
            AssetType.SWITCH,
            AssetType.VM,
        ]
    elif re.search(r"\bfirewall\b", text):
        preference = [AssetType.FIREWALL, AssetType.APPLICATION_SERVER]
    else:
        preference = [AssetType.APPLICATION_SERVER, AssetType.WEB_SERVER, AssetType.VM]

    for preferred in preference:
        for asset in candidates:
            if asset.type is preferred:
                return asset
    return candidates[0]


@lru_cache(maxsize=1)
def load_mock_assets() -> tuple[Asset, ...]:
    """Load the mock OSS/network inventory (immutable tuple for caching)."""
    import json

    raw = json.loads(ASSETS_PATH.read_text())
    return tuple(Asset.model_validate(item) for item in raw)


def mock_assets() -> list[Asset]:
    return list(load_mock_assets())
