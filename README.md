# NetBoss-XT CRA Agent

Local-first POC for CRA Class I / Category 6 Network Management Systems.

- **Flow 1** — document intelligence and draft control registry generation.
- **Flow 2** — deterministic evidence collection against an approved registry.
- **Flow 3** — deterministic assessment and technical readiness report.
- **Flow 4** — advisory remediation, evidence-backed verification and the final report.

## Requirements

- Python 3.12+
- Source PDFs under `documents/authoritative/` and `documents/supporting/`
- Product profile: `product/nextboss_xt_product_profile.yaml`
- Security assertions: `policy/security_assertions.yaml`
- Runtime target profile: `targets/*.json` (Flow 2 only)

## Setup

```bash
cd ~/nextboss-cra-agent
/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

The web UI is an optional extra so the CLI and the existing test suite stay
installable without FastAPI:

```bash
pip install -e ".[ui]"
```

## Web UI

A local-first workspace over the same Python functions the CLI calls. It does
not introduce another agent, does not recalculate verdicts in the browser, and
does not expose a shell.

```bash
source .venv/bin/activate
nextboss-cra serve
# open http://127.0.0.1:8000
```

`serve` binds to loopback by default. The UI has no authentication, so do not
bind it to another interface unless you understand that every artifact on this
machine would be reachable.

Walk through:

1. **Sources & Registry** — review the source documents, build / validate /
   approve the control registry.
2. **Evidence** — pick a target from `targets/*.json` and collect evidence
   (or run the full assessment chain).
3. **Assessment** — read PASS / FAIL / evidence-gap verdicts and the
   evaluator trace for any control.
4. **Remediation & Verify** — propose and approve advisory actions; apply only
   against the demo target through an allow-listed executor; then re-scan to
   verify. Application alone does not close a finding.
5. **Reports** — open any historical run, download JSON, or the generated
   HTML report.

The CLI remains the source of truth for automation. Equivalent commands are
shown on the Registry page under **Advanced — equivalent CLI**.

## Flow 1 CLI

```bash
# Ingest documents and build registries (deterministic, no network)
nextboss-cra ingest

# Validate draft registries (citations, MCP tools, product/policy refs)
nextboss-cra validate-registry

# Human review summary (includes security-area coverage table)
nextboss-cra review-registry

# Approve and create immutable versioned baseline
nextboss-cra approve-registry --approver "Your Name" --version 1.1.0
```

## Flow 2 CLI

```bash
# Collect evidence for the latest approved registry using the mock provider
nextboss-cra collect-evidence --target targets/nextboss-demo.mock.json

# Pin a scenario, an application, a registry version, or a reproducible run ID
nextboss-cra collect-evidence --scenario compliant
nextboss-cra collect-evidence --application router_monitor
nextboss-cra collect-evidence --registry registry/approved/controls.approved.v1.1.0.json
nextboss-cra collect-evidence --run-id RUN-DEMO-0001
```

Flow 2 is deterministic and has no AI agent. The approved `evidence_plan` is
the scan plan: the runner resolves parameters, calls only the MCP capabilities
the registry names, and records collection outcomes. It emits no PASS / FAIL /
PARTIAL, evaluates no security assertion, and reads no CRA or ETSI document.

An approved registry is refused unless its `status` is `APPROVED` and its
content hash matches the approval manifest. Evidence requests whose parameters
are `<TO_BE_PROVIDED>` fail closed as `NOT_COLLECTED` /
`PARAMETER_UNRESOLVED` rather than being guessed.

## Flow 3 CLI

Assessment needs an approved registry and a collected evidence run. From a
fresh checkout the shortest path is:

```bash
# 1. Activate the venv (after Setup above)
source .venv/bin/activate

# 2. Collect evidence (skip if evidence/<run-id>/ already exists)
nextboss-cra collect-evidence --run-id RUN-DEMO-0001

# 3. Assess that run and write the report
nextboss-cra assess --run-id RUN-DEMO-0001

# 4. Open the HTML report
open assessments/RUN-DEMO-0001/assessment.html
```

Optional flags:

```bash
# Assert the evidence was collected against a specific target
nextboss-cra assess --run-id RUN-DEMO-0001 --target-id nextboss-demo

# Pin a registry version instead of using the latest approved
nextboss-cra assess --run-id RUN-DEMO-0001 \
  --registry registry/approved/controls.approved.v1.1.0.json

# Enable Agent 2 narration (explanations only; verdicts stay deterministic)
nextboss-cra assess --run-id RUN-DEMO-0001 --llm
```

Flow 3 writes `assessments/<run-id>/assessment.json` and `assessment.html`. It
reads the approved registry and the evidence run and modifies neither.

Every verdict comes from the deterministic rule engine, which evaluates the
`evaluation.rules` the approved registry already carries. Agent 2 is the only
LLM-dependent part and it explains verdicts it is given: the application accepts
back only `expected_state`, `observed_state` and `reason`, so a model cannot
change a verdict, a severity, an identifier, a hash or a summary count. With
narration disabled — the default — explanations are generated from the evaluator
trace instead. If a configured model fails, the deterministic assessment is kept
and an `LLM_NARRATIVE_UNAVAILABLE` limitation is recorded.

Verdict precedence is fixed:

1. `NOT_APPLICABLE` when the approved control says so
2. `HUMAN_REVIEW_REQUIRED` when applicability is unresolved, or the control has
   no deterministic rule
3. `INSUFFICIENT_EVIDENCE` when a rule needs an observation the run did not
   collect — missing evidence is never read as compliance
4. otherwise `PASS` when every mandatory rule matches, else `FAIL`

`PARTIAL` is reachable only through an explicit approved `partial_when`
condition, so it never means "some rules passed". An unsupported operator or a
rule this evaluator cannot execute yields `HUMAN_REVIEW_REQUIRED` with the error
recorded, never a silent `PASS` and never `FAIL`.

The report is generated from application templates as a single self-contained
HTML file. There is no compliance percentage or score, and it states throughout
that it is an automated technical readiness assessment rather than CRA
certification or a statement of legal conformity. Findings carry severity
`UNCLASSIFIED` because the registry defines no approved severity model.

## Flow 4 CLI

Remediation finalises an assessed run. It needs nothing new: the approved
registry, the evidence run and the assessment are already on disk.

```bash
# 1. Activate the venv (after Setup above)
source .venv/bin/activate

# 2. Assess a run first, if you have not already (see Flow 3 above)
nextboss-cra assess --run-id RUN-DEMO-0001

# 3. Compose advisory remediation and render the final report
nextboss-cra remediate --run-id RUN-DEMO-0001

# 4. Open the final report
open assessments/RUN-DEMO-0001/final-report.html
```

Optional flags:

```bash
# Pin a registry version instead of using the latest approved
nextboss-cra remediate --run-id RUN-DEMO-0001 \
  --registry registry/approved/controls.approved.v1.1.0.json

# Read evidence and assessments from somewhere other than the defaults
nextboss-cra remediate --run-id RUN-DEMO-0001 \
  --evidence-dir evidence --assessments-dir assessments

# Include closure status for an earlier run's findings
nextboss-cra remediate --run-id RUN-DEMO-0002 --previous-run RUN-DEMO-0001
```

### Verifying closure after a re-scan

A system owner applies the change outside this application, or — for the demo
target only — proposes, approves and applies an allow-listed remediation action.
Application lands in `APPLIED_UNVERIFIED` and does **not** change the assessment
verdict or finding status. Verification then means running Flow 2 and Flow 3
again and comparing the two assessments:

```bash
# Optional demo path: propose → approve → apply (nextboss-demo only)
nextboss-cra propose-remediation --run-id RUN-DEMO-0001 --control-id NMS-CRA-0006
nextboss-cra approve-remediation --run-id RUN-DEMO-0001 --control-id NMS-CRA-0006 \
  --approver "Your Name"
nextboss-cra apply-remediation --run-id RUN-DEMO-0001 --control-id NMS-CRA-0006

# 1. Collect evidence again into a new run
#    (--scenario is a mock-provider convenience; a real target needs no flag)
#    Keep the same scenario when testing demo overlay patches.
nextboss-cra collect-evidence --run-id RUN-DEMO-0002 --scenario vulnerable

# 2. Assess the new run
nextboss-cra assess --run-id RUN-DEMO-0002

# 3. Compare the runs and write the closure decision
nextboss-cra verify --previous-run RUN-DEMO-0001 --new-run RUN-DEMO-0002

# 4. Or fold that same comparison into the new final report
nextboss-cra remediate --run-id RUN-DEMO-0002 --previous-run RUN-DEMO-0001
open assessments/RUN-DEMO-0002/final-report.html
```

Both Flow 4 commands exit non-zero and write nothing if an input is refused.

| Command | Writes |
|---------|--------|
| `remediate --run-id X` | `assessments/X/remediation.json`, `assessments/X/final-report.html` |
| `verify --previous-run A --new-run B` | `assessments/B/verification.json` |

It reads the approved registry, the evidence run and the assessment, and
modifies none of them.

Flow 4 has no AI agent. A technical recommendation is the approved control's
`remediation_seed.recommendation` copied verbatim, with finding context —
observed state, the approved rules that did not match, evidence IDs — quoted
from the assessment. Nothing is composed, no command is generated, and
`automatic_execution` is `false` on every item. If a failing control has no
approved remediation guidance, the item becomes a `HUMAN_REVIEW` action with
reason code `REMEDIATION_GUIDANCE_NOT_APPROVED` rather than an improvised fix.

Each verdict maps to exactly one outcome:

| Verdict | Action |
|---------|--------|
| `FAIL`, `PARTIAL` | `TECHNICAL_REMEDIATION` from the approved seed |
| `INSUFFICIENT_EVIDENCE` | `EVIDENCE_RESOLUTION` — obtain the evidence, not a fix |
| `HUMAN_REVIEW_REQUIRED` | `HUMAN_REVIEW` — state the decision, never convert it |
| `PASS`, `NOT_APPLICABLE` | no item |

Preflight aborts before anything is composed unless the registry is `APPROVED`
and matches its manifest, and the evidence and assessment both name that exact
registry hash, the same run and the same target. Flow 4 never calls
Infrastructure MCP: a re-scan means running Flow 2 and Flow 3 again.

The status model implements `OPEN` and `VERIFIED_CLOSED` only for findings.
A separate remediation-action lifecycle (`PROPOSED` → `AWAITING_APPROVAL` →
`APPROVED` → `APPLYING` → `APPLIED_UNVERIFIED` → `VERIFIED`, plus `FAILED` /
`ROLLED_BACK` / `BLOCKED`) records controlled demo execution. A finding closes
only when a later assessment returns `PASS` for the same control, on the same
target, under the same approved registry hash, backed by evidence the new run
actually collected. A recommendation does not close a finding and neither does
a statement that a fix was applied — the verifier's only inputs are two
assessment documents, so there is nothing to assert a claim through. If the
approved registry changed between the two runs, the comparison returns
`VERIFICATION_BLOCKED` with `REGISTRY_BASELINE_CHANGED`; the control may be
reassessed under the new baseline, but that is not closure under the old one.

The final report is assembled deterministically from the stored JSON artifacts
and reuses the Flow 3 report sections, so control IDs, verdicts, evidence
references, source traceability and registry metadata are never rebuilt. When
the provider is `mock` it opens with a `SYNTHETIC / MOCK ASSESSMENT DATA`
banner.

## Inputs

| Path | Role |
|------|------|
| `documents/authoritative/` | Binding CRA / classification PDFs |
| `documents/supporting/` | Guidance, ETSI, standardisation context |
| `product/nextboss_xt_product_profile.yaml` | NetBoss-XT interfaces, ports, config paths (not a legal source) |
| `policy/security_assertions.yaml` | Internal technical assertion baseline (not CRA legal text) |
| `targets/*.json` | Runtime target profile: where a scan runs (Flow 2) |

The product profile describes what NetBoss-XT *is*; the target profile
describes *where* a scan runs. A target profile carries only secret
*references* such as `credential_ref`, never key or password material.

Unknown application paths in the product profile stay as `<TO_BE_PROVIDED>` and
are never invented by Agent 1.

## Outputs

- `registry/document_registry.json`
- `registry/controls.draft.json` (includes `target_context`, enriched
  `evidence_plan`, and `assertion_refs`)
- `registry/approved/controls.approved.vX.Y.Z.json` (after approval)
- `evidence/<run-id>/evidence.json` and `evidence/<run-id>/raw/EV-*.json`
  (after collection)
- `assessments/<run-id>/assessment.json` and `assessments/<run-id>/assessment.html`
  (after assessment)
- `assessments/<run-id>/remediation.json` and
  `assessments/<run-id>/final-report.html` (after remediation)
- `assessments/<run-id>/verification.json` (after verifying against an earlier run)

## Infrastructure MCP

Fourteen read-only capabilities are registered in
[src/mcp/](src/mcp/README.md). There is no generic shell tool and no argument
accepts a command string. Paths supplied by an approved control must still pass
the MCP path allowlist, results are size-bounded, and secrets are redacted at
the provider boundary before anything reaches disk.

`MockProvider` serves three synthetic scenarios — `compliant`, `partial` and
`vulnerable` — selected by the target profile's `environment` field. Fixtures
are demo data for testing the evidence contract, not statements about real
NetBoss-XT. `SSHProvider` is not part of this baseline; it slots in behind the
same `Provider` interface without changing the evidence contract.

## Evidence path contract

See [docs/evidence_namespace.md](docs/evidence_namespace.md) for the normalized
evidence fields that deterministic rules address, including which paths Flow 2
collects and which are derived downstream.
