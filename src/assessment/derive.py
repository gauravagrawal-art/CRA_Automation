"""Rule paths computed by Flow 3 rather than observed by Flow 2.

Three approved rule paths cannot be collected, because deciding that a listener
is unexpected or an account is a vendor default requires the policy baseline,
and Flow 2 must not read it. The collector supplies the facts; this module
applies the policy to them.

Derivations are written into a copy of the normalized evidence. The evidence
artifacts on disk are never modified.
"""

from __future__ import annotations

import copy
from typing import Any

from src.config import DEFAULT_ACCOUNT_NAMES, NON_LOGIN_SHELLS
from src.policy.assertions import SecurityAssertions


def _derive_certificates_expired(namespace: dict[str, Any]) -> tuple[Any, str] | None:
    """``certificates.expired`` — true when any in-scope certificate is expired."""
    if "expired" in namespace:
        return None
    certificates = namespace.get("certificates")
    if not isinstance(certificates, list):
        return None
    expired = any(bool(cert.get("expired")) for cert in certificates if isinstance(cert, dict))
    return expired, f"any of {len(certificates)} observed certificate(s) expired"


def _derive_unexpected_listeners(
    namespace: dict[str, Any], policy: SecurityAssertions
) -> tuple[Any, str] | None:
    """``open_ports.unexpected_listeners`` — listeners outside the expected set."""
    if "unexpected_listeners" in namespace:
        return None
    listeners = namespace.get("listeners")
    if not isinstance(listeners, list):
        return None
    expected = set(policy.network.expected_ports)
    unexpected = [
        listener
        for listener in listeners
        if isinstance(listener, dict) and listener.get("port") not in expected
    ]
    return unexpected, f"listeners on ports outside the expected set {sorted(expected)}"


def _is_usable_account(account: dict[str, Any]) -> bool:
    """A default account only matters while it can still be logged into."""
    if account.get("locked"):
        return False
    shell = account.get("shell")
    return not (isinstance(shell, str) and shell in NON_LOGIN_SHELLS)


def _derive_default_accounts(namespace: dict[str, Any]) -> tuple[Any, str] | None:
    """``local_users.default_accounts`` — usable vendor/default accounts.

    Omitted entirely when none are present, so the approved ``NOT_EXISTS``
    condition resolves as the registry intends.
    """
    if "default_accounts" in namespace:
        return None
    accounts = namespace.get("accounts")
    if not isinstance(accounts, list):
        return None
    matches = [
        account.get("username")
        for account in accounts
        if isinstance(account, dict)
        and account.get("username") in DEFAULT_ACCOUNT_NAMES
        and _is_usable_account(account)
    ]
    if not matches:
        return None
    return matches, "usable accounts matching the internal vendor-default name list"


def derive_paths(
    normalized: dict[str, Any], policy: SecurityAssertions
) -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """Return an augmented copy of ``normalized`` plus ``(path, basis)`` pairs."""
    augmented = copy.deepcopy(normalized)
    derived: list[tuple[str, str]] = []

    handlers = {
        ("certificates", "expired"): lambda ns: _derive_certificates_expired(ns),
        ("open_ports", "unexpected_listeners"): lambda ns: _derive_unexpected_listeners(ns, policy),
        ("local_users", "default_accounts"): lambda ns: _derive_default_accounts(ns),
    }

    for (root, leaf), handler in handlers.items():
        namespace = augmented.get(root)
        if not isinstance(namespace, dict):
            continue
        outcome = handler(namespace)
        if outcome is None:
            continue
        value, basis = outcome
        namespace[leaf] = value
        derived.append((f"{root}.{leaf}", basis))

    return augmented, derived
