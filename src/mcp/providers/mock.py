"""Deterministic mock provider backed by synthetic fixtures.

Fixtures are synthetic demo data used to exercise the evidence contract. They
are NOT assertions about real NextBoss-XT, and they deliberately encode no
compliance verdict — a scenario name describes the shape of the synthetic
target, not a conclusion about it.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.mcp.errors import SourceUnavailableError
from src.mcp.policy import enforce_file_size
from src.mcp.providers.base import Provider

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
SCENARIOS = ("compliant", "partial", "vulnerable")


@lru_cache(maxsize=None)
def _load_fixture(scenario: str) -> dict[str, Any]:
    path = FIXTURES_DIR / f"{scenario}.json"
    if not path.exists():
        raise ValueError(
            f"Unknown mock scenario '{scenario}'. Expected one of: {', '.join(SCENARIOS)}"
        )
    return json.loads(path.read_text())


class MockProvider(Provider):
    """Serves fixture data for one synthetic target scenario."""

    name = "mock"

    def __init__(self, target_id: str, scenario: str = "compliant") -> None:
        super().__init__(target_id)
        if scenario not in SCENARIOS:
            raise ValueError(
                f"Unknown mock scenario '{scenario}'. Expected one of: {', '.join(SCENARIOS)}"
            )
        self.scenario = scenario
        self._fixture = _load_fixture(scenario)

    def _section(self, key: str) -> Any:
        return json.loads(json.dumps(self._fixture.get(key)))

    def get_system_info(self) -> dict[str, Any]:
        return self._section("system_info") or {}

    def get_users(self) -> dict[str, Any]:
        return {"users": self._section("users") or []}

    def get_groups(self) -> dict[str, Any]:
        return {"groups": self._section("groups") or []}

    def get_services(self) -> dict[str, Any]:
        return {"services": self._section("services") or []}

    def get_open_ports(self, port: int | None = None) -> dict[str, Any]:
        listeners = self._section("listeners") or []
        if port is not None:
            listeners = [item for item in listeners if item.get("port") == port]
        return {"listeners": listeners, "scope_port": port}

    def get_processes(self) -> dict[str, Any]:
        return {"processes": self._section("processes") or []}

    def get_file(self, path: str) -> dict[str, Any]:
        entry = (self._section("files") or {}).get(path)
        if entry is None:
            raise SourceUnavailableError(f"File '{path}' is not present on the target")
        enforce_file_size(path, int(entry.get("size_bytes", 0)))
        return {"path": path, **entry}

    def get_file_permissions(self, path: str) -> dict[str, Any]:
        entry = (self._section("file_permissions") or {}).get(path)
        if entry is None:
            raise SourceUnavailableError(
                f"Permissions for '{path}' are not observable on the target"
            )
        return {"path": path, **entry}

    def get_network_configuration(self) -> dict[str, Any]:
        return self._section("network_configuration") or {}

    def get_firewall_rules(self) -> dict[str, Any]:
        return self._section("firewall") or {}

    def get_tls_configuration(self, host: str, port: int) -> dict[str, Any]:
        entry = (self._section("tls") or {}).get(str(port))
        if entry is None:
            return {"host": host, "port": port, "reachable": False}
        return {"host": host, "port": port, **entry}

    def get_certificates(self, host: str, port: int) -> dict[str, Any]:
        entry = (self._section("certificates") or {}).get(str(port))
        if entry is None:
            return {"host": host, "port": port, "observed": False, "certificates": []}
        return {"host": host, "port": port, **entry}

    def get_installed_packages(self) -> dict[str, Any]:
        return {"packages": self._section("packages") or []}

    def get_security_logs(
        self,
        source: str | None = None,
        max_entries: int = 100,
        time_range_hours: int = 24,
    ) -> dict[str, Any]:
        sources = self._section("security_logs") or {}
        key = source or "default"
        entry = sources.get(key)
        if entry is None:
            raise SourceUnavailableError(
                f"Security log source '{key}' is not available on the target"
            )
        entries = entry.get("entries", [])
        return {
            "source": entry.get("source", key),
            "available": entry.get("available", True),
            "logging_enabled": entry.get("logging_enabled", True),
            "time_range_hours": time_range_hours,
            "max_entries": max_entries,
            "returned_entries": len(entries[:max_entries]),
            "truncated": len(entries) > max_entries,
            "entries": entries[:max_entries],
        }
