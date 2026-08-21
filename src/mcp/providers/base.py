"""Provider interface for the fourteen read-only capabilities.

Every method is a read. There is deliberately no generic shell/exec capability
and no method that changes files, services, users, packages, network or
firewall state — swapping a provider therefore cannot change what the evidence
contract is able to express.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Provider(ABC):
    """Read-only evidence source for a single target."""

    #: Short provider name recorded on every result, e.g. ``mock`` or ``ssh``.
    name: str = "abstract"

    def __init__(self, target_id: str) -> None:
        self.target_id = target_id

    @abstractmethod
    def get_system_info(self) -> dict[str, Any]:
        """Hostname, OS, version, kernel, architecture."""

    @abstractmethod
    def get_users(self) -> dict[str, Any]:
        """Local user/account metadata. Password material is never returned."""

    @abstractmethod
    def get_groups(self) -> dict[str, Any]:
        """Groups and memberships relevant to access-control evidence."""

    @abstractmethod
    def get_services(self) -> dict[str, Any]:
        """Service name, state, enablement, executable metadata when available."""

    @abstractmethod
    def get_open_ports(self, port: int | None = None) -> dict[str, Any]:
        """Normalized listener information, optionally scoped to one port."""

    @abstractmethod
    def get_processes(self) -> dict[str, Any]:
        """Constrained process inventory without command-line secrets."""

    @abstractmethod
    def get_file(self, path: str) -> dict[str, Any]:
        """Contents of an allowlisted file, subject to size limits."""

    @abstractmethod
    def get_file_permissions(self, path: str) -> dict[str, Any]:
        """Owner, group, mode and ACL metadata for an allowlisted path."""

    @abstractmethod
    def get_network_configuration(self) -> dict[str, Any]:
        """Interfaces, addresses, routes and DNS."""

    @abstractmethod
    def get_firewall_rules(self) -> dict[str, Any]:
        """Normalized firewall state and relevant rules."""

    @abstractmethod
    def get_tls_configuration(self, host: str, port: int) -> dict[str, Any]:
        """Transport-security facts observed at a declared endpoint."""

    @abstractmethod
    def get_certificates(self, host: str, port: int) -> dict[str, Any]:
        """Certificate subject, issuer, validity, SANs and chain metadata."""

    @abstractmethod
    def get_installed_packages(self) -> dict[str, Any]:
        """Package inventory only. No vulnerability determination."""

    @abstractmethod
    def get_security_logs(
        self,
        source: str | None = None,
        max_entries: int = 100,
        time_range_hours: int = 24,
    ) -> dict[str, Any]:
        """Bounded security log excerpt from an approved source."""

    def close(self) -> None:
        """Release any connection held by the provider."""
