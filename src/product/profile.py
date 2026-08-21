"""Product profile loading for NextBoss-XT."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

from src.config import PRODUCT_PROFILE_PATH, TO_BE_PROVIDED


def is_resolved(path: str | None) -> bool:
    """Return True when a config path is present and not the unresolved sentinel."""
    if path is None:
        return False
    return path.strip() != TO_BE_PROVIDED and path.strip() != ""


class ProductInfo(BaseModel):
    name: str
    type: str


class CraContext(BaseModel):
    class_: str = Field(alias="class")
    category: int | str
    category_name: str

    model_config = {"populate_by_name": True}


class Platform(BaseModel):
    operating_system: str


class Interface(BaseModel):
    name: str
    type: str
    protocol: str
    port: int


class Authentication(BaseModel):
    mechanisms: list[str] = Field(default_factory=list)


class ProductConfiguration(BaseModel):
    tls_config_file: str = TO_BE_PROVIDED
    application_config: str = TO_BE_PROVIDED
    ssh_config_file: str = TO_BE_PROVIDED
    postgres_config_file: str = TO_BE_PROVIDED


class ProductProfile(BaseModel):
    product: ProductInfo
    cra_context: CraContext
    platform: Platform
    interfaces: list[Interface] = Field(default_factory=list)
    authentication: Authentication = Field(default_factory=Authentication)
    configuration: ProductConfiguration = Field(default_factory=ProductConfiguration)

    def interface_by_name(self, name: str) -> Interface | None:
        for iface in self.interfaces:
            if iface.name == name:
                return iface
        return None

    def declared_ports(self) -> set[int]:
        return {iface.port for iface in self.interfaces}

    def declared_component_names(self) -> set[str]:
        return {iface.name for iface in self.interfaces}


def load_product_profile(
    path: Path | None = None,
) -> tuple[ProductProfile, str]:
    """Load and validate the product profile; return (model, sha256 of raw bytes)."""
    profile_path = path or PRODUCT_PROFILE_PATH
    if not profile_path.exists():
        raise FileNotFoundError(f"Product profile not found: {profile_path}")
    raw = profile_path.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    data = yaml.safe_load(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Product profile must be a mapping: {profile_path}")
    return ProductProfile.model_validate(data), sha256
