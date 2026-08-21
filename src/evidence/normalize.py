"""Deterministic normalization of tool results into the evidence namespace.

Every normalizer is plain code. No model is involved, and no normalizer decides
whether a value is acceptable — comparisons against policy belong to the
downstream assessment layer.

Two namespace paths in `docs/evidence_namespace.md` are deliberately *not*
produced here: `open_ports.unexpected_listeners` and
`local_users.default_accounts`. Both require the expected-port set and the
vendor-account list from `policy/security_assertions.yaml`, which Flow 2 must
not load. The factual inputs (`open_ports.listeners`, `local_users.accounts`)
are produced instead.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

SSH_CONFIG_PATHS = ("/etc/ssh/sshd_config",)
SSH_CONFIG_DIR_PREFIX = "/etc/ssh/sshd_config.d/"

# Canonical OpenSSH spellings for the keywords addressed by evaluation rules.
# sshd_config keywords are case-insensitive on the target; normalized evidence
# uses one stable spelling so rule paths resolve.
_SSHD_CANONICAL = {
    "permitrootlogin": "PermitRootLogin",
    "permitemptypasswords": "PermitEmptyPasswords",
    "passwordauthentication": "PasswordAuthentication",
    "pubkeyauthentication": "PubkeyAuthentication",
    "port": "Port",
    "protocol": "Protocol",
    "x11forwarding": "X11Forwarding",
    "maxauthtries": "MaxAuthTries",
    "loglevel": "LogLevel",
    "ciphers": "Ciphers",
    "macs": "MACs",
    "kexalgorithms": "KexAlgorithms",
    "clientaliveinterval": "ClientAliveInterval",
    "clientalivecountmax": "ClientAliveCountMax",
    "allowusers": "AllowUsers",
    "allowgroups": "AllowGroups",
    "permittunnel": "PermitTunnel",
    "usepam": "UsePAM",
}


class NormalizationError(Exception):
    """Raised when a tool result cannot be normalized.

    The sanitized raw artifact is retained regardless; the evidence item is
    recorded as PARSE_ERROR with ``normalized = null``.
    """


def _require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NormalizationError(f"{label} is {type(value).__name__}, expected object")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise NormalizationError(f"{label} is {type(value).__name__}, expected array")
    return value


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise NormalizationError(f"{label} is not an ISO-8601 timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NormalizationError(f"{label} is not an ISO-8601 timestamp: {value}") from exc


def is_ssh_config_path(path: str) -> bool:
    return path in SSH_CONFIG_PATHS or path.startswith(SSH_CONFIG_DIR_PREFIX)


def parse_sshd_config(content: str) -> dict[str, Any]:
    """Parse sshd_config text into effective keyword values.

    OpenSSH applies the first occurrence of a keyword, so later duplicates are
    recorded separately rather than overwriting. ``Match`` blocks are reported
    but their conditional bodies are not merged into the effective values.
    """
    effective: dict[str, Any] = {}
    duplicates: list[str] = []
    match_blocks: list[str] = []
    in_match = False

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        keyword = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""

        if keyword.lower() == "match":
            in_match = True
            match_blocks.append(value)
            continue
        if in_match:
            continue

        canonical = _SSHD_CANONICAL.get(keyword.lower(), keyword)
        if canonical in effective:
            duplicates.append(canonical)
            continue
        effective[canonical] = value

    effective["_duplicate_keywords"] = sorted(set(duplicates))
    effective["_match_blocks"] = match_blocks
    return effective


def _normalize_system_info(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    return {
        "system_info": {
            "hostname": data.get("hostname"),
            "os": data.get("os"),
            "version": data.get("version"),
            "kernel": data.get("kernel"),
            "architecture": data.get("architecture"),
        }
    }


def _normalize_users(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    users = _require_list(data.get("users"), "users")
    accounts = []
    for entry in users:
        item = _require_dict(entry, "user entry")
        accounts.append(
            {
                "username": item.get("username"),
                "uid": item.get("uid"),
                "gid": item.get("gid"),
                "shell": item.get("shell"),
                "home": item.get("home"),
                "locked": item.get("locked"),
                "last_login": item.get("last_login"),
                # The hash itself is redacted upstream; its presence is a fact.
                "has_password_hash": "password_hash" in item,
            }
        )
    return {"local_users": {"accounts": accounts, "count": len(accounts)}}


def _normalize_groups(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    groups = _require_list(data.get("groups"), "groups")
    normalized = []
    for entry in groups:
        item = _require_dict(entry, "group entry")
        members = _require_list(item.get("members", []), "group members")
        normalized.append(
            {
                "group": item.get("group"),
                "gid": item.get("gid"),
                "members": members,
                "member_count": len(members),
            }
        )
    return {"local_groups": {"groups": normalized, "count": len(normalized)}}


def _normalize_services(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    services = _require_list(data.get("services"), "services")
    inventory = []
    for entry in services:
        item = _require_dict(entry, "service entry")
        inventory.append(
            {
                "name": item.get("name"),
                "state": item.get("state"),
                "enabled": item.get("enabled"),
                "executable": item.get("executable"),
                "description": item.get("description"),
            }
        )
    return {
        "services": {
            "inventory": inventory,
            "count": len(inventory),
            "running": [s["name"] for s in inventory if s.get("state") == "running"],
        }
    }


def _normalize_open_ports(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    listeners = _require_list(data.get("listeners"), "listeners")
    normalized = []
    for entry in listeners:
        item = _require_dict(entry, "listener entry")
        normalized.append(
            {
                "address": item.get("address"),
                "port": item.get("port"),
                "transport": item.get("transport"),
                "process": item.get("process"),
            }
        )
    normalized.sort(key=lambda item: (item.get("port") or 0, str(item.get("address"))))
    return {
        "open_ports": {
            "scope_port": data.get("scope_port", args.get("port")),
            "listeners": normalized,
            "listener_count": len(normalized),
            "ports": sorted({item["port"] for item in normalized if item["port"] is not None}),
        }
    }


def _normalize_processes(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    processes = _require_list(data.get("processes"), "processes")
    inventory = []
    for entry in processes:
        item = _require_dict(entry, "process entry")
        inventory.append(
            {
                "pid": item.get("pid"),
                "user": item.get("user"),
                "name": item.get("name"),
                "cmdline_summary": item.get("cmdline_summary"),
            }
        )
    return {"processes": {"inventory": inventory, "count": len(inventory)}}


def _normalize_file(args: dict[str, Any], data: dict[str, Any], now: str) -> dict[str, Any]:
    path = data.get("path") or args.get("path")
    content = data.get("content")
    if not isinstance(content, str):
        raise NormalizationError(f"File content for '{path}' is not text")

    result: dict[str, Any] = {
        "file": {
            "path": path,
            "size_bytes": data.get("size_bytes"),
            "encoding": data.get("encoding"),
            "truncated": bool(data.get("truncated", False)),
            "line_count": len(content.splitlines()),
        }
    }
    if isinstance(path, str) and is_ssh_config_path(path):
        result["ssh_config"] = parse_sshd_config(content)
    return result


def _normalize_file_permissions(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    path = data.get("path") or args.get("path")
    mode = data.get("mode")
    if not isinstance(mode, str) or not mode:
        raise NormalizationError(f"Permission mode for '{path}' is missing")
    try:
        mode_bits = int(mode, 8)
    except ValueError as exc:
        raise NormalizationError(f"Permission mode '{mode}' is not octal") from exc

    return {
        "file_permissions": {
            "path": path,
            "owner": data.get("owner"),
            "group": data.get("group"),
            "mode": mode,
            "world_writable": bool(mode_bits & 0o002),
            "world_readable": bool(mode_bits & 0o004),
            "group_writable": bool(mode_bits & 0o020),
            "setuid": bool(mode_bits & 0o4000),
            "acl": data.get("acl", []),
        }
    }


def _normalize_network_configuration(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    interfaces = _require_list(data.get("interfaces", []), "interfaces")
    routes = _require_list(data.get("routes", []), "routes")
    dns = _require_dict(data.get("dns", {}), "dns")
    return {
        "network_configuration": {
            "interfaces": interfaces,
            "routes": routes,
            "dns": {
                "servers": dns.get("servers", []),
                "search": dns.get("search", []),
            },
            "interface_count": len(interfaces),
        }
    }


def _normalize_firewall_rules(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    rules = _require_list(data.get("rules", []), "firewall rules")
    return {
        "firewall_rules": {
            "backend": data.get("backend"),
            "state": data.get("state"),
            "enabled": data.get("enabled"),
            "default_zone": data.get("default_zone"),
            "rules": rules,
            "rule_count": len(rules),
        }
    }


def _normalize_tls_configuration(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    reachable = bool(data.get("reachable", False))
    protocols = data.get("protocols") or {}
    if reachable:
        protocols = _require_dict(protocols, "tls protocols")
    ciphers = data.get("cipher_suites") or []
    if reachable:
        ciphers = _require_list(ciphers, "cipher_suites")

    return {
        "tls_configuration": {
            "endpoint": {"host": data.get("host", args.get("host")), "port": data.get("port", args.get("port"))},
            "reachable": reachable,
            "protocols": {key: bool(value) for key, value in protocols.items()},
            "cipher_suites": list(ciphers),
            "negotiated": data.get("negotiated"),
        }
    }


def _normalize_certificates(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    observed = bool(data.get("observed", False))
    certificates = _require_list(data.get("certificates", []), "certificates")
    reference = _parse_timestamp(now, "collection timestamp")

    entries = []
    any_expired = False
    for entry in certificates:
        item = _require_dict(entry, "certificate entry")
        not_after_raw = item.get("not_after")
        expired: bool | None = None
        if not_after_raw is not None:
            expired = _parse_timestamp(not_after_raw, "certificate not_after") < reference
            any_expired = any_expired or expired
        entries.append(
            {
                "position": item.get("position"),
                "subject": item.get("subject"),
                "issuer": item.get("issuer"),
                "not_before": item.get("not_before"),
                "not_after": not_after_raw,
                "expired": expired,
                "sans": item.get("sans", []),
                "signature_algorithm": item.get("signature_algorithm"),
                "key": item.get("key"),
                "self_signed": item.get("self_signed", item.get("subject") == item.get("issuer")),
            }
        )

    return {
        "certificates": {
            "endpoint": {"host": data.get("host", args.get("host")), "port": data.get("port", args.get("port"))},
            "observed": observed,
            "chain_complete": data.get("chain_complete"),
            # Unknown rather than false when nothing was observed.
            "expired": any_expired if entries else None,
            "certificate_count": len(entries),
            "certificates": entries,
            "evaluated_at": now,
        }
    }


def _normalize_installed_packages(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    packages = _require_list(data.get("packages"), "packages")
    inventory = []
    for entry in packages:
        item = _require_dict(entry, "package entry")
        inventory.append(
            {
                "name": item.get("name"),
                "version": item.get("version"),
                "source": item.get("source"),
            }
        )
    inventory.sort(key=lambda item: str(item.get("name")))
    # Inventory only. Whether a version is vulnerable is not decided here.
    return {"installed_packages": {"inventory": inventory, "count": len(inventory)}}


def _normalize_security_logs(
    args: dict[str, Any], data: dict[str, Any], now: str
) -> dict[str, Any]:
    entries = _require_list(data.get("entries", []), "log entries")
    return {
        "security_logs": {
            "source": data.get("source"),
            "available": bool(data.get("available", False)),
            "logging_enabled": data.get("logging_enabled"),
            "time_range_hours": data.get("time_range_hours"),
            "entry_count": len(entries),
            "truncated": bool(data.get("truncated", False)),
            "entries": entries,
        }
    }


NORMALIZERS: dict[str, Callable[[dict[str, Any], dict[str, Any], str], dict[str, Any]]] = {
    "get_system_info": _normalize_system_info,
    "get_users": _normalize_users,
    "get_groups": _normalize_groups,
    "get_services": _normalize_services,
    "get_open_ports": _normalize_open_ports,
    "get_processes": _normalize_processes,
    "get_file": _normalize_file,
    "get_file_permissions": _normalize_file_permissions,
    "get_network_configuration": _normalize_network_configuration,
    "get_firewall_rules": _normalize_firewall_rules,
    "get_tls_configuration": _normalize_tls_configuration,
    "get_certificates": _normalize_certificates,
    "get_installed_packages": _normalize_installed_packages,
    "get_security_logs": _normalize_security_logs,
}


def normalize(
    tool: str, arguments: dict[str, Any], data: dict[str, Any], collected_at: str
) -> dict[str, Any]:
    """Normalize one sanitized tool result into the canonical schema."""
    normalizer = NORMALIZERS.get(tool)
    if normalizer is None:
        raise NormalizationError(f"No normalizer registered for tool '{tool}'")
    return normalizer(arguments, _require_dict(data, f"result of '{tool}'"), collected_at)
