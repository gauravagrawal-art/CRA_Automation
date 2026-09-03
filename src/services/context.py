"""Deterministic workspace state: what stage the assessment is in and what to do next.

Every value here is derived from artifacts on disk. No model is consulted, so
the guidance the UI gives is reproducible and matches what the CLI would refuse
or allow.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.config import (
    APPLICATIONS,
    MCP_CAPABILITY_CATALOG,
    PRODUCT_NAME,
    TARGETS_DIR,
)
from src.display import application_label, target_env_label
from src.evidence.targets import MOCK_SCENARIOS, TargetProfile, load_target_profile
from src.services import runs_service
from src.services.registry_service import RegistryState, registry_state
from src.services.runs_service import RunOverview

#: The workflow the stepper renders, in order.
STAGES = [
    ("assessment", "Assessment"),
    ("controls", "Controls"),
    ("evidence", "Evidence"),
    ("findings", "Findings"),
    ("remediation", "Remediation"),
    ("report", "Report"),
]

_STAGE_INDEX = {key: i for i, (key, _) in enumerate(STAGES)}


@dataclass
class TargetOption:
    """A target profile discovered on disk.

    The UI offers these by name only. A path never comes from the browser, so
    no request can point a scan at an arbitrary file.
    """

    key: str
    path: Path
    target_id: str
    provider: str
    environment: str
    host: str
    supported: bool = True
    detail: str = ""

    @property
    def label(self) -> str:
        env = target_env_label(self.target_id)
        if self.provider == "mock":
            return env
        return f"{env} ({self.provider} / {self.host})"


def list_targets(targets_dir: Path | None = None) -> list[TargetOption]:
    """Every valid target profile in the targets directory.

    ``.example`` files are skipped: they are documentation, not runnable
    targets. An unparseable profile is listed as unsupported with the reason,
    rather than hidden.
    """
    base = targets_dir or TARGETS_DIR
    options: list[TargetOption] = []
    if not base.exists():
        return options

    for path in sorted(base.glob("*.json")):
        try:
            profile, _ = load_target_profile(path)
        except Exception as exc:
            options.append(
                TargetOption(
                    key=path.name,
                    path=path,
                    target_id=path.stem,
                    provider="unknown",
                    environment="",
                    host="",
                    supported=False,
                    detail=str(exc),
                )
            )
            continue

        options.append(
            TargetOption(
                key=path.name,
                path=path,
                target_id=profile.target_id,
                provider=profile.provider,
                environment=profile.environment,
                host=profile.host,
                supported=profile.provider == "mock",
                detail=(
                    ""
                    if profile.provider == "mock"
                    else "The SSH provider is not part of this baseline; only mock "
                    "targets can be scanned."
                ),
            )
        )
    return options


def find_target(key: str, targets_dir: Path | None = None) -> TargetOption | None:
    """Resolve a target by its filename key. Returns None for anything unknown."""
    for option in list_targets(targets_dir):
        if option.key == key:
            return option
    return None


def default_target(targets: list[TargetOption] | None = None) -> TargetOption | None:
    options = targets if targets is not None else list_targets()
    for option in options:
        if option.supported:
            return option
    return options[0] if options else None


@dataclass
class Capability:
    """A runtime capability shown in the header. Never carries a credential."""

    name: str
    available: bool
    detail: str

    @property
    def label(self) -> str:
        return "Available" if self.available else "Not configured"


def capabilities() -> list[Capability]:
    """Which optional runtime pieces are wired up.

    Both LLM roles are advisory in this POC and neither is configured with a
    real model, so both report honestly rather than implying an AI is running.
    """
    return [
        Capability(
            "Agent 1 LLM",
            False,
            "Registry generation is deterministic in this build. No model is called.",
        ),
        Capability(
            "Agent 2 LLM",
            False,
            "Verdict explanations come from deterministic templates. A model could "
            "only rewrite prose; it can never change a verdict.",
        ),
        Capability(
            "Infrastructure MCP",
            True,
            f"{len(MCP_CAPABILITY_CATALOG)} read-only capabilities registered. "
            "There is no shell tool and no argument accepts a command string.",
        ),
    ]


@dataclass
class NextAction:
    """The single thing the user should do next, and why."""

    headline: str
    detail: str
    cta: str
    href: str
    tone: str = "action"


@dataclass
class WorkspaceContext:
    """Everything the shell (header, sidebar, stepper) and Overview need."""

    product: str = PRODUCT_NAME
    registry: RegistryState = field(default_factory=RegistryState)
    targets: list[TargetOption] = field(default_factory=list)
    runs: list[RunOverview] = field(default_factory=list)
    latest: RunOverview | None = None
    stage: str = "sources"
    next_action: NextAction | None = None
    capabilities: list[Capability] = field(default_factory=list)

    @property
    def stage_index(self) -> int:
        return _STAGE_INDEX.get(self.stage, 0)

    @property
    def provider(self) -> str:
        if self.latest and self.latest.provider:
            return self.latest.provider
        target = default_target(self.targets)
        return target.provider if target else "—"

    @property
    def target_id(self) -> str:
        if self.latest and self.latest.target_id:
            return self.latest.target_id
        target = default_target(self.targets)
        return target.target_id if target else "—"

    @property
    def target_env(self) -> str:
        return target_env_label(self.target_id)

    @property
    def application_id(self) -> str:
        return self.latest.application_id if self.latest else ""

    @property
    def application_name(self) -> str:
        return application_label(self.application_id)

    @property
    def is_mock(self) -> bool:
        return self.provider == "mock"

    @property
    def last_run_at(self) -> str:
        return self.latest.started_at if self.latest else ""

    @property
    def open_findings(self) -> int:
        return self.latest.open_findings if self.latest else 0

    @property
    def evidence_gaps(self) -> int:
        return self.latest.evidence_gaps if self.latest else 0

    @property
    def human_review(self) -> int:
        return self.latest.human_review if self.latest else 0

    def stage_states(self) -> list[dict[str, str]]:
        """Per-step state for the progress stepper: done, current or pending."""
        current = self.stage_index
        steps = []
        for index, (key, label) in enumerate(STAGES):
            if index < current:
                state = "done"
            elif index == current:
                state = "current"
            else:
                state = "pending"
            steps.append({"key": key, "label": label, "state": state})
        return steps


def _derive_stage(registry: RegistryState, latest: RunOverview | None) -> str:
    """Map artifact state onto the user-facing compliance workflow steps."""
    if latest is None or not latest.has_assessment:
        if latest is not None and latest.has_evidence:
            return "evidence"
        return "assessment"
    if latest.open_findings or (latest.has_remediation and not latest.has_verification):
        if not latest.has_remediation:
            return "findings"
        return "remediation"
    if latest.has_remediation or latest.has_verification:
        return "report"
    return "controls"


def _derive_next_action(
    registry: RegistryState,
    latest: RunOverview | None,
    targets: list[TargetOption],
) -> NextAction:
    """Pick one action from artifact state alone. Order is the workflow order."""
    if not registry.draft_exists and not registry.scannable:
        return NextAction(
            headline="No control registry exists yet",
            detail=(
                "Agent 1 reads the CRA, classification and ETSI source documents and "
                "proposes a draft control registry. Nothing is scanned at this step."
            ),
            cta="Build draft registry",
            href="/registry",
        )

    if not registry.scannable:
        return NextAction(
            headline=f"Registry is still DRAFT ({registry.draft_controls} controls)",
            detail=(
                "A draft cannot be scanned against. Validate it, review the controls, "
                "then approve to create an immutable versioned baseline."
            ),
            cta="Review and approve controls",
            href="/registry",
        )

    if not any(t.supported for t in targets):
        return NextAction(
            headline="No scannable target profile found",
            detail=(
                "Add a target profile under targets/ describing where the scan should "
                "run. Only the mock provider is available in this baseline."
            ),
            cta="Open Evidence",
            href="/evidence",
            tone="blocked",
        )

    if latest is None or not latest.has_evidence:
        return NextAction(
            headline=f"Registry approved (v{registry.latest_version}), no scan exists",
            detail=(
                "Collect evidence against the approved registry. Collection is "
                "read-only and makes no compliance decision."
            ),
            cta="Collect evidence",
            href="/evidence",
        )

    if latest.error:
        return NextAction(
            headline=f"Run {latest.run_id} could not be read",
            detail=latest.error,
            cta="Open Reports",
            href="/reports",
            tone="blocked",
        )

    if not latest.has_assessment:
        return NextAction(
            headline=f"Evidence collected for {latest.run_id}, not yet assessed",
            detail=(
                "Run the deterministic assessment to turn collected evidence into "
                "verdicts against the approved rules."
            ),
            cta="Run assessment",
            href="/assessment",
        )

    if not latest.has_remediation:
        return NextAction(
            headline=f"{latest.run_id} is assessed but has no remediation plan",
            detail=(
                "Compose advisory remediation to group findings into technical fixes, "
                "evidence gaps and human decisions."
            ),
            cta="Compose remediation",
            href="/remediation",
        )

    if latest.open_findings:
        if latest.has_verification:
            return NextAction(
                headline=f"{latest.open_findings} finding(s) remain open after verification",
                detail=(
                    "Apply the remaining changes on the target outside this "
                    "application, then re-scan and verify again."
                ),
                cta="Review remediation",
                href="/remediation",
            )
        return NextAction(
            headline=f"{latest.open_findings} finding(s) are open",
            detail=(
                "Review the recommended actions. Once a change has been applied on "
                "the target, re-scan and verify: only a new evidence-backed PASS "
                "closes a finding."
            ),
            cta="Review remediation",
            href="/remediation",
        )

    if not latest.has_verification:
        return NextAction(
            headline="No open findings in the latest run",
            detail=(
                "Nothing requires remediation. Re-scan and verify against an earlier "
                "run to record closure for its findings."
            ),
            cta="Open Remediation & Verify",
            href="/remediation",
            tone="ok",
        )

    return NextAction(
        headline=f"All findings verified closed for {latest.run_id}",
        detail=(
            "Every finding was closed by a later evidence-backed PASS under the same "
            "approved baseline. Open the final report for the full record."
        ),
        cta="Open final report",
        href=f"/runs/{latest.run_id}",
        tone="ok",
    )


def workspace() -> WorkspaceContext:
    """Assemble the whole workspace picture from disk in one pass."""
    registry = registry_state()
    targets = list_targets()
    runs = runs_service.list_runs()
    latest = runs_service.latest_run(runs)

    return WorkspaceContext(
        registry=registry,
        targets=targets,
        runs=runs,
        latest=latest,
        stage=_derive_stage(registry, latest),
        next_action=_derive_next_action(registry, latest, targets),
        capabilities=capabilities(),
    )


def scenarios() -> tuple[str, ...]:
    """Mock scenarios a user may pin, straight from the target contract."""
    return MOCK_SCENARIOS


def applications() -> tuple[tuple[str, str], ...]:
    """Applications offered in the Target Env dropdown."""
    return APPLICATIONS


def target_profile_for(option: TargetOption) -> TargetProfile:
    profile, _ = load_target_profile(option.path)
    return profile
