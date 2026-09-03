"""Build concise display strings from collected evidence and control results.

Does not invent observations. Facts are derived only from evaluator traces,
normalized evidence payloads, and approved remediation seeds.
"""

from __future__ import annotations

import re
from typing import Any

from src.assessment.models import ControlResult, Verdict
from src.compliance.models import DisplaySeverity, EvidenceFact, UIStatus
from src.evidence.models import EvidenceItem, EvidenceRun

_MAX_SENTENCE = 160


def _one_sentence(text: str, limit: int = _MAX_SENTENCE) -> str:
    text = re.sub(r"\s+", " ", (text or "").strip())
    if not text:
        return ""
    # Prefer the first sentence.
    for sep in (". ", "; ", " — ", " - "):
        if sep in text:
            text = text.split(sep, 1)[0].strip()
            break
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    if text and text[-1] not in ".!?":
        text += "."
    return text


def short_requirement(result: ControlResult) -> str:
    legal = result.legal_requirement or {}
    for key in ("normalized_requirement", "original_text"):
        value = legal.get(key) if isinstance(legal, dict) else None
        if value:
            return _one_sentence(str(value))
    if result.technical_control:
        return _one_sentence(result.technical_control)
    if result.title:
        # Titles often look like "CRA I.1: long text"
        title = result.title.split(":", 1)[-1].strip() if ":" in result.title else result.title
        return _one_sentence(title)
    return "Approved control requirement applies."


def _tls_fact(normalized: dict[str, Any], port: int | None) -> str | None:
    protocols = normalized.get("protocols") or {}
    enabled = [name for name, on in protocols.items() if on]
    if not enabled and isinstance(protocols, dict):
        # Alternate shape: { "TLSv1_0": true, ... }
        enabled = [k for k, v in protocols.items() if v]
    if not enabled:
        return None
    port_bit = f" on port {port}" if port else ""
    # Prefer a short list of protocol names.
    labels = []
    for name in enabled:
        label = str(name).replace("_", ".").replace("TLSv", "TLS ").replace("TLS.", "TLS ")
        labels.append(label if label.startswith("TLS") else str(name))
    return f"{', '.join(labels[:4])} detected{port_bit}."


def _path_fact(path: str, observed: Any) -> str | None:
    path = path or ""
    value = observed
    if isinstance(value, list) and len(value) == 1:
        value = value[0]

    if "tls" in path.lower() or "protocol" in path.lower():
        return f"{path.split('.')[-1]} observed as {value}."
    if "PermitRootLogin" in path:
        return f"PermitRootLogin is {value}."
    if "PermitEmptyPasswords" in path:
        return f"PermitEmptyPasswords is {value}."
    if "default_accounts" in path or "local_users" in path:
        if isinstance(value, list):
            names = ", ".join(str(v) for v in value[:4])
            return f"Default or retained accounts present: {names}." if names else None
        return f"Local account observation: {value}."
    if "listeners" in path or "open_ports" in path:
        return f"Listener observation: {value}."
    if path:
        short = path.rsplit(".", 1)[-1]
        return f"{short} = {value}."
    return None


def evidence_facts(
    result: ControlResult,
    evidence_by_id: dict[str, EvidenceItem],
) -> list[EvidenceFact]:
    """Build at most two short evidence facts from the run."""
    facts: list[EvidenceFact] = []
    seen: set[str] = set()

    def add(text: str | None, ids: list[str]) -> None:
        if not text:
            return
        cleaned = _one_sentence(text)
        if cleaned in seen:
            return
        seen.add(cleaned)
        facts.append(EvidenceFact(text=cleaned, evidence_ids=list(ids)))

    # Prefer unmatched (or all) rule observations.
    entries = list(result.evaluator_trace or [])
    failed = [e for e in entries if not e.matched]
    for entry in (failed or entries)[:3]:
        add(_path_fact(str(entry.rule.get("path", "")), entry.observed), list(entry.evidence_ids))
        if len(facts) >= 2:
            return facts

    for eid in result.evidence_ids:
        item = evidence_by_id.get(eid)
        if not item or not item.normalized:
            continue
        port = None
        if isinstance(item.parameters_redacted, dict):
            port = item.parameters_redacted.get("port")
        if item.tool == "get_tls_configuration":
            add(_tls_fact(item.normalized, port), [eid])
        elif item.tool == "get_users":
            users = item.normalized.get("users") or []
            names = [u.get("username") for u in users if isinstance(u, dict) and u.get("username")]
            notable = [n for n in names if n in {"admin", "root", "guest", "default", "nextboss"}]
            if notable:
                add(f"Accounts present: {', '.join(notable)}.", [eid])
        elif item.tool == "get_open_ports":
            listeners = item.normalized.get("listeners") or []
            ports = sorted({int(l.get("port")) for l in listeners if isinstance(l, dict) and l.get("port")})
            if ports:
                add(f"Open ports: {', '.join(str(p) for p in ports[:8])}.", [eid])
        if len(facts) >= 2:
            break

    if not facts and result.observed_state:
        add(result.observed_state, list(result.evidence_ids))
    if not facts and result.evidence_gaps:
        keys = ", ".join(g.evidence_key for g in result.evidence_gaps[:3])
        add(f"Required evidence not collected: {keys}.", [])
    return facts[:2]


def short_finding(result: ControlResult, status: UIStatus, facts: list[EvidenceFact]) -> str:
    if status in (UIStatus.PASS, UIStatus.NOT_APPLICABLE):
        return ""
    if status is UIStatus.REVIEW:
        if result.evidence_gaps:
            keys = ", ".join(g.evidence_key for g in result.evidence_gaps[:2])
            return _one_sentence(f"Evidence incomplete: {keys}")
        return _one_sentence(result.reason or "Human review required.")
    # FAIL
    if facts:
        return facts[0].text
    failed = [e for e in (result.evaluator_trace or []) if not e.matched]
    if failed:
        fact = _path_fact(str(failed[0].rule.get("path", "")), failed[0].observed)
        if fact:
            return _one_sentence(fact)
    return _one_sentence(result.reason or result.observed_state or "Control did not meet the approved condition.")


def short_reason(result: ControlResult, status: UIStatus, finding: str) -> str:
    if status is UIStatus.PASS:
        return "All approved conditions matched."
    if status is UIStatus.NOT_APPLICABLE:
        reason = (result.applicability or {}).get("reason") if isinstance(result.applicability, dict) else None
        return _one_sentence(str(reason) or "Control is out of scope.")
    if finding:
        return finding
    return _one_sentence(result.reason or "Further review required.")


def short_remediation(result: ControlResult, status: UIStatus) -> str:
    if status in (UIStatus.PASS, UIStatus.NOT_APPLICABLE):
        return ""
    seed = result.remediation_seed or {}
    rec = (seed.get("recommendation") or "").strip() if isinstance(seed, dict) else ""
    if rec and not rec.lower().startswith("review and align"):
        return _one_sentence(rec, limit=200)
    # Derive a concise action from the unmatched path when the seed is generic.
    failed = [e for e in (result.evaluator_trace or []) if not e.matched]
    if failed:
        path = str(failed[0].rule.get("path", ""))
        if "TLSv1_0" in path or "TLSv1_1" in path or "tls" in path.lower():
            return "Disable TLS 1.0 and TLS 1.1. Allow TLS 1.2 or TLS 1.3 only."
        if "PermitRootLogin" in path:
            return "Set PermitRootLogin to no in sshd_config and reload sshd."
        if "PermitEmptyPasswords" in path:
            return "Set PermitEmptyPasswords to no and reload sshd."
        if "default_accounts" in path or "local_users" in path:
            return "Disable or remove default admin accounts. Keep only required named accounts."
        if "firewall" in path.lower():
            return "Restrict inbound exposure to approved management interfaces only."
        if "5432" in path or "postgres" in path.lower() or "listeners" in path:
            return "Bind the service to approved interfaces and remove unnecessary listeners."
    if status is UIStatus.REVIEW:
        return "Collect the missing approved evidence and reassess."
    return _one_sentence(rec or "Align configuration with the approved control and reassess.", limit=200)


def short_verification(result: ControlResult, status: UIStatus) -> str:
    if status in (UIStatus.PASS, UIStatus.NOT_APPLICABLE):
        return ""
    seed = result.remediation_seed or {}
    keys = seed.get("verification_evidence_keys") if isinstance(seed, dict) else None
    if keys:
        return f"Rescan and confirm approved evidence keys: {', '.join(str(k) for k in keys[:3])}."
    failed = [e for e in (result.evaluator_trace or []) if not e.matched]
    if failed:
        path = str(failed[0].rule.get("path", ""))
        if "tls" in path.lower():
            return "Rescan the management HTTPS endpoint and confirm only approved TLS protocols are available."
        if "ssh" in path.lower() or "PermitRoot" in path:
            return "Rescan SSH configuration and confirm the approved settings are in effect."
    if status is UIStatus.REVIEW:
        return "Re-collect the missing evidence and reassess the control."
    return "Rescan the same control under the same approved registry and confirm PASS."


def display_severity(result: ControlResult, status: UIStatus) -> DisplaySeverity:
    """Presentation-only severity overlay. Does not write back to assessment.json."""
    if status in (UIStatus.PASS, UIStatus.NOT_APPLICABLE):
        return DisplaySeverity.NONE
    if status is UIStatus.REVIEW:
        return DisplaySeverity.MEDIUM

    text = " ".join(
        [
            result.control_id,
            result.title,
            result.observed_state,
            result.reason,
            " ".join(str(e.rule.get("path", "")) for e in (result.evaluator_trace or [])),
        ]
    ).lower()

    if any(k in text for k in ("tls1_0", "tlsv1_0", "tls 1.0", "empty password", "telnet", "default admin")):
        return DisplaySeverity.CRITICAL
    if any(k in text for k in ("tls", "ssh", "rootlogin", "firewall", "authentication", "password", "5432")):
        return DisplaySeverity.HIGH
    if result.verdict is Verdict.PARTIAL:
        return DisplaySeverity.MEDIUM
    return DisplaySeverity.HIGH


def index_evidence(run: EvidenceRun | None) -> dict[str, EvidenceItem]:
    if not run:
        return {}
    return {item.evidence_id: item for item in run.evidence}
