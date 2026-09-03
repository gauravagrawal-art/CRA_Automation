"""Display labels for Target Env and Applications."""

from __future__ import annotations

from src.config import DEFAULT_APPLICATION_ID, DEMO_TARGET_ID, PRODUCT_NAME
from src.display import (
    application_label,
    known_application,
    normalize_application_id,
    resolve_application_id,
    scope_caption,
    scope_short,
    target_env_label,
)
from src.evidence.models import RunMetadata
from src.services.context import list_targets


def test_demo_target_displays_as_product_name() -> None:
    assert PRODUCT_NAME == "NetBoss-XT"
    assert target_env_label(DEMO_TARGET_ID) == "NetBoss-XT"
    assert target_env_label("other-host") == "other-host"
    assert target_env_label("") == "—"


def test_application_catalog() -> None:
    assert application_label("router_monitor") == "Router Monitor"
    assert application_label("switch_monitor") == "Switch Monitor"
    assert application_label("sbc_monitor") == "SBC Monitor"
    assert known_application("Router Monitor")
    assert known_application("sbc_monitor")
    assert not known_application("vulnerable")
    assert normalize_application_id("Switch Monitor") == "switch_monitor"
    assert resolve_application_id(None) == DEFAULT_APPLICATION_ID
    assert resolve_application_id("") == DEFAULT_APPLICATION_ID


def test_scope_lines() -> None:
    assert scope_short(DEMO_TARGET_ID, "router_monitor") == "NetBoss-XT · Router Monitor"
    assert (
        scope_caption(DEMO_TARGET_ID, "switch_monitor")
        == "Assessment done on Target Env: NetBoss-XT · Application: Switch Monitor"
    )
    assert (
        scope_caption(DEMO_TARGET_ID, "sbc_monitor", verb="Remediation for")
        == "Remediation for Target Env: NetBoss-XT · Application: SBC Monitor"
    )
    assert scope_caption(DEMO_TARGET_ID, "") == "Assessment done on Target Env: NetBoss-XT"


def test_legacy_run_metadata_without_application_id_loads() -> None:
    meta = RunMetadata.model_validate(
        {
            "run_id": "RUN-LEGACY",
            "target_id": DEMO_TARGET_ID,
            "registry_version": "1.0.0",
            "registry_hash": "abc",
            "registry_path": "registry/approved/x.json",
            "target_profile_hash": "def",
            "provider": "mock",
            "started_at": "2026-01-01T00:00:00+00:00",
        }
    )
    assert meta.application_id == ""
    assert target_env_label(meta.target_id) == "NetBoss-XT"


def test_target_option_label_hides_internal_id() -> None:
    options = list_targets()
    demo = next(t for t in options if t.target_id == DEMO_TARGET_ID)
    assert demo.label == "NetBoss-XT"
    assert "nextboss-demo" not in demo.label
