# NetBoss-XT CRA Agent — Demo Guide

**Audience:** anyone in the room (product, engineering, compliance, leadership)  
**Time:** about 30 minutes  
**What this is:** a local proof-of-concept that checks whether a Network Management System (NetBoss-XT) looks technically ready against EU CRA Class I / Category 6 requirements.

---

## Say this first (30 seconds)

This tool does **not** certify CRA legal conformity.

It does four practical jobs:

1. Read official CRA PDFs and turn them into a **control list** we can review and approve.
2. Collect **technical evidence** from a target (today: synthetic demo data).
3. Compare that evidence against **fixed rules** and give PASS / FAIL / needs review.
4. Propose **remediation**, apply it only on the demo target, then **re-scan** to prove the finding actually closed.

Everything you will see today is **mock / synthetic**. The yellow banner is intentional.

There is **no compliance score or percentage**. A control either matches the approved rules, or it does not, or a human must decide.

---

## The big picture

```text
CRA PDFs + product profile + security policy
                 │
                 ▼
        1. Sources & Registry
           (what to check)
                 │  human approves
                 ▼
        2. Evidence collection
           (what is actually on the target)
                 │
                 ▼
        3. Assessment
           (PASS / FAIL / review)
                 │
                 ▼
        4. Remediation + verify
           (fix on demo → re-scan → close)
                 │
                 ▼
        Reports + Audit log
```

The **web UI** and the **CLI** call the same Python functions. The UI does not invent verdicts in the browser.

Start the UI:

```bash
source .venv/bin/activate
nextboss-cra serve
# open http://127.0.0.1:8000
```

---

## Demo script (half hour)

Use this order. Do not skip the honesty lines.

| Min | Where in UI | What to show | What to say |
|-----|-------------|--------------|-------------|
| 0–2 | Home / Assessment | Mock banner, Target Env: NetBoss-XT, application (Router Monitor / Switch Monitor / SBC Monitor), registry status | “This is a technical readiness workspace, not a certificate. Data is synthetic.” |
| 2–7 | **Sources & Registry** | Documents, draft controls, Build / Validate / Approve | “PDFs become a versioned control registry. Nothing is scanned until a human approves it.” |
| 7–12 | **Evidence** | Collect evidence, open one item (users, TLS, ports) | “Collection is read-only. This step does **not** decide PASS/FAIL.” |
| 12–18 | **Assessment**, then one control | Verdict, rule trace, evidence used | “The rule engine is the only thing that can say PASS or FAIL. Missing evidence is not treated as a fail.” |
| 18–22 | **Controls** and **Findings** | Asset mapping, open findings | “Controls are mapped to a mock 12-asset inventory. Findings stay OPEN until a later scan proves PASS.” |
| 22–27 | **Remediation** | Propose → Approve → Apply on `NMS-CRA-0006` (TLS) | “Apply only patches the demo overlay. It does **not** close the finding.” |
| 27–30 | Re-collect → re-assess → **Audit** / **Report** | Finding can move to VERIFIED_CLOSED | “Closure is evidence-backed. A claim that we applied a fix is not enough.” |

**Best live story:** start from the **vulnerable** mock target (default), show FAILs, apply TLS hardening (`NMS-CRA-0006`), re-scan, show the finding close.

Demo-only apply works for four controls:

| Control | What the demo “fix” does |
|---------|--------------------------|
| `NMS-CRA-0005` | Disable default accounts and harden SSH |
| `NMS-CRA-0006` | Turn off TLS 1.0/1.1 and restore valid certs |
| `NMS-CRA-0007` | Harden `sshd_config` permissions |
| `NMS-CRA-0011` | Close unexpected ports (telnet, open postgres, extra UI port) |

If time is short: skip Controls/Findings and do Registry → Evidence → one Assessment control → Remediation apply.

---

## 1. How the flow works

### Flow 1 — Sources & Registry

**Question it answers:** *What should we check, and how?*

1. The app looks for expected PDFs under `documents/authoritative/` and `documents/supporting/`.
2. It extracts CRA Annex I requirements (about **22 points**).
3. For each point it builds a control (`NMS-CRA-0001` …).
4. A human **validates** (citations, tools, product/policy references) then **approves**.
5. Approval creates an immutable file under `registry/approved/` with a content hash.

Until approval, the registry is only a **draft**. Evidence collection will refuse it.

### Flow 2 — Evidence

**Question it answers:** *What did we observe on the target?*

1. Load the **approved** registry (hash must match the approval manifest).
2. Follow each control’s evidence plan: which tool to call, with which parameters.
3. Talk to Infrastructure MCP (today: **MockProvider** serving JSON fixtures).
4. Normalize results, redact secrets, write `evidence/<run-id>/`.

This step is **collection only**. Words like PASS / FAIL are forbidden in its output.

If a product path is still `<TO_BE_PROVIDED>`, that evidence is marked **not collected** — the app does not guess.

### Flow 3 — Assessment

**Question it answers:** *Does the observed configuration match the approved rules?*

1. Preflight: same registry hash, same target, evidence actually exists.
2. For each control, the rule engine evaluates only the evidence that control asked for.
3. Write `assessments/<run-id>/assessment.json` and an HTML report.

Optional LLM narration can **explain** a verdict. It cannot change it.

### Flow 4 — Remediation and verification

**Question it answers:** *What should change, and did a later scan prove it closed?*

1. FAIL / PARTIAL → copy the approved recommendation (no invented shell commands).
2. Missing evidence → “get the evidence”, not “fix the system”.
3. Human-review controls stay human-review.
4. On the demo target only: propose → named approve → apply an allow-listed overlay.
5. Apply lands in **APPLIED_UNVERIFIED**. Finding stays **OPEN**.
6. Re-collect + re-assess. A finding becomes **VERIFIED_CLOSED** only if the later run is PASS on the **same control, same target, same approved registry hash**.

### Audit

The Audit tab does not invent people or dates. It reads what is already on disk: registry approval, assessment timestamps, remediation approvals.

---

## 2. How CRA documents become controls

This is the part people usually ask first.

### Input documents (expected files)

| Folder | File | Role |
|--------|------|------|
| `documents/authoritative/` | `CELEX_02024R2847-20241120_EN_TXT.pdf` | Binding CRA regulation. Annex I is where requirements come from. |
| `documents/authoritative/` | `OJ_L_202502392_EN_TXT.pdf` | Official classification (Category 6 = Network Management Systems). |
| `documents/supporting/` | `C_2026_5252_CRA_Guidance.pdf` | Commission guidance (not binding). |
| `documents/supporting/` | `ETSI_EN_304_621_V1.0.5.pdf` | Technical standard used as a crosswalk to CRA points. |
| `documents/supporting/` | `C_2025_618_CRA_Standardisation_Request.pdf` | Standardisation request (context). |

These PDFs are **not stored in git**. They must be present locally for ingest to extract live text. Missing supporting files are recorded as unresolved; they are not invented.

Two more files are **not legal text**. They tell the agent what NetBoss-XT *is* and what *our* technical baseline is:

| File | Role |
|------|------|
| `product/nextboss_xt_product_profile.yaml` | Interfaces and ports: UI 8443, API 443, PostgreSQL 5432, SSH 22. Some config paths are still `<TO_BE_PROVIDED>`. |
| `policy/security_assertions.yaml` | Internal rules: no TLS 1.0/1.1, expected ports, SSH root-login / empty-password policy, no world-writable configs. |

### Pipeline (simple)

```text
1. Inventory     List expected PDFs, hash them, count pages.
2. Parse         Extract text from each PDF page.
3. Classify      Is this binding law, guidance, or a standard?
4. Extract       Find Annex I Part I and Part II points by pattern matching.
5. Crosswalk     Link ETSI clauses to those CRA points (if the ETSI PDF is present).
6. Derive        One control per CRA point:
                   - Is it technical (we can scan) or documentary (a person must supply proof)?
                   - Which MCP tools to call?
                   - Which deterministic rules to run later?
                   - A short remediation seed (pre-approved wording).
7. Write         registry/document_registry.json
                 registry/controls.draft.json
8. Human         Validate → review → approve (versioned, hashed).
```

### What a control contains

Each control (`NMS-CRA-00xx`) is a structured object, not a free-text essay:

- **Legal source** — which CRA sentence, which page (citation must be a real substring of the PDF).
- **NMS interpretation** — what this means for NetBoss-XT.
- **Evidence plan** — tools such as `get_tls_configuration`, `get_users`, `get_open_ports`.
- **Evaluation rules** — for example “TLS 1.0 must be false”.
- **Remediation seed** — the sentence that Flow 4 will copy later.

**Technical vs documentary**

- **Technical** (examples: TLS, accounts, file permissions, open ports): can be scanned.
- **Documentary** (examples: secure design process, vulnerability handling procedures): need documents or a human. These come back as **HUMAN_REVIEW_REQUIRED**, not as fake PASSes.

About **22 controls** are created — one per Annex I point the extractor finds.

IDs that make a good demo:

- `NMS-CRA-0005` — access control / default accounts (CRA I-2-d)
- `NMS-CRA-0006` — cryptography / TLS (CRA I-2-e)
- `NMS-CRA-0007` — config file permissions (CRA I-2-f)
- `NMS-CRA-0011` — attack surface / unexpected ports (CRA I-2-j)

LLM assist is **optional**. By default there is no model. Prose can be helped by an LLM; tools, rules, and citations stay deterministic.

---

## 3. Logics used (plain language)

### Document reading

- PDF text extraction, then cleanup.
- Regex / pattern match for “ANNEX I” and the lettered points `(a)` … `(m)` and Part II `(1)`–`(8)`.
- Filename → document ID map (e.g. the CELEX PDF → `CRA-2024-2847`).
- Content fingerprints to classify authority (binding vs guidance).
- Citation check: the quoted excerpt must actually appear in the PDF.
- Injection scan: treat PDF text as untrusted data (no “ignore previous instructions” execution).

### Control creation

- **8 security areas** (TLS, network exposure, SSH, PostgreSQL, accounts, RBAC, file permissions, and related coverage) map CRA points to tools and ports from the product profile.
- Unknown paths stay `<TO_BE_PROVIDED>` — never invented.
- Remediation wording is a short template from the control’s area (TLS / SSH / ports / accounts), not a generated playbook.

### Evidence collection

- 14 **read-only** tools. No generic shell. No command string.
- Path allowlist (e.g. `/etc/ssh/sshd_config`). Other paths are refused.
- Size limits and secret redaction (passwords, tokens, private keys) before anything is saved.
- Mock provider picks a **scenario** from the target file: `vulnerable` (default demo), `partial`, or `compliant`.

### Assessment (the important one)

Verdicts are decided in a fixed order:

1. **NOT_APPLICABLE** — approved control says this does not apply.
2. **HUMAN_REVIEW_REQUIRED** — no deterministic rule, or applicability still unresolved.
3. **INSUFFICIENT_EVIDENCE** — we needed a fact we did not collect. **This is not a FAIL.**
4. **PASS** — every mandatory rule matched.
5. **FAIL** — a mandatory rule did not match.
6. **PARTIAL** — only if the approved control defines a special `partial_when` condition (none do today).

Rules are simple comparisons: equals, not equals, exists, contains, greater/less than, in a list.

Some facts are **derived at assessment time**, not at collection time, because collection is not allowed to apply policy:

| Derived fact | Meaning |
|--------------|---------|
| Expired certificates | Any in-scope cert is expired |
| Unexpected listeners | Open port is not in the expected set (22, 443, 8443, 5432) |
| Default accounts | A usable account named admin / guest / etc. |

### UI status (simplified)

| Engine verdict | What the UI often shows |
|----------------|-------------------------|
| PASS | PASS |
| FAIL, PARTIAL | FAIL |
| NOT_APPLICABLE | NOT_APPLICABLE |
| HUMAN_REVIEW_REQUIRED, INSUFFICIENT_EVIDENCE | REVIEW |

### Asset mapping (UI)

A mock inventory of **12 assets** (app server, DB, switches, router, firewall, load balancer, container, …) is matched to controls with keyword rules (TLS → HTTPS-managed assets, SSH → SSH-capable assets, postgres → database, and so on). This is for display and applicability in the UI. It is not a live CMDB.

### Remediation

- Copy the approved seed. Do not generate `systemctl` commands.
- Demo apply = merge slices from the **compliant** fixture onto the **vulnerable** fixture **in memory**. Disk fixtures are not rewritten.
- Human evidence analyser (demo) is phrase matching, e.g. “default admin account has been disabled”. Weak phrases like “password policy was reviewed” do not pass.

### What is deliberately *not* logic

- No % compliant.
- No severity scoring (every finding is `UNCLASSIFIED`).
- No “the LLM said so, so it is PASS”.

---

## 4. Reference and mock data files

These are the files behind the demo. None of them are a statement about real NetBoss-XT in production.

### Runtime target

| File | What it is |
|------|------------|
| `targets/nextboss-demo.mock.json` | Demo target. `provider: mock`, `environment: vulnerable`. Change `environment` to `compliant` or `partial` to change the story. |
| `targets/nextboss-lab.ssh.json.example` | Shape of a future SSH target. **Not runnable today.** |

### Synthetic “machine” snapshots (what the mock tools return)

| File | Story |
|------|--------|
| `src/mcp/providers/fixtures/vulnerable.json` | TLS 1.0/1.1, expired certs, usable `admin` account, telnet on port 23, world-writable sshd_config. **Default demo.** |
| `src/mcp/providers/fixtures/partial.json` | Mixed posture — some issues fixed, some not. |
| `src/mcp/providers/fixtures/compliant.json` | Hardened TLS, no default accounts, expected ports only. Also the source of demo “apply” patches. |

### Product and policy (real config, not mock machines)

| File | What it is |
|------|------------|
| `product/nextboss_xt_product_profile.yaml` | What NetBoss-XT exposes (ports, interfaces). |
| `policy/security_assertions.yaml` | Our internal technical baseline used by rules. |

### UI asset inventory

| File | What it is |
|------|------------|
| `src/compliance/fixtures/assets.json` | 12 fake OSS/NMS assets for Controls / Findings mapping. |

### Prompt specs (reference, not runtime unless LLM is enabled)

| File | What it is |
|------|------------|
| `prompts/agent1_document_control_intelligence.md` | Full spec for how controls should be derived. |
| `prompts/agent1_execution_model.md` | Step table of the actual pipeline. |
| `prompts/agent2_assessment_reporting.md` | Narration-only rules (cannot change verdicts). |

### Created at runtime (after you click the buttons)

| Path | Created by |
|------|------------|
| `registry/document_registry.json` | Flow 1 ingest |
| `registry/controls.draft.json` | Flow 1 ingest |
| `registry/approved/controls.approved.vX.Y.Z.json` | Approval |
| `evidence/<run-id>/` | Evidence collection |
| `assessments/<run-id>/` | Assessment, remediation, reports |
| `proposals/` | Cached LLM assist, if ever enabled |

---

## 5. Left for later (enhancements and integrations)

Be explicit in the demo: this is a **POC with clean seams**, not a finished product.

| Area | Today | Later |
|------|--------|--------|
| Talking to a real host | Mock JSON fixtures | SSH (or similar) provider behind the **same** 14-tool contract |
| CRA PDFs | Local files in fixed folders | Upload UI, versioned document store |
| Control wording | Templates + optional cached LLM | Real model assist, still unable to write rules or citations |
| Assessment narration | Built from the evaluator trace | Agent 2 / LLM explanation only |
| Human evidence | Phrase matching | Local model (e.g. Ollama) returning the **same** decision schema |
| Asset inventory | 12-row mock JSON | CMDB / discovery feed |
| Remediation apply | 4 allow-listed demo operations | Real change tickets / ITSM; still never close without a re-scan |
| Auth / multi-user | None (loopback only) | Login, roles, approval workflow |
| Severity / risk | Unclassified | An **approved** severity model, then wired in |
| Config paths | Several `<TO_BE_PROVIDED>` | Fill product profile so more evidence actually collects |
| Network | Designed to run offline | Optional model APIs; MCP still read-only |

Planned-but-not-built names you may hear:

- `SSHProvider`
- `OllamaComplianceProvider`
- `OllamaEvidenceAnalyzer` (qwen3:8b)

The important design choice: those can be swapped in **without** letting a model decide PASS/FAIL.

---

## 6. What could be done better

Honest list. Useful if someone asks “what’s next?” or “what would you change?”

1. **Document extraction is brittle.** Annex I is found with regular expressions on PDF text. Layout changes, translations, or a new CRA version can miss points. A structured legal corpus or better layout-aware parsing would be more robust.

2. **Controls are one-per-Annex-I-point.** Real programmes usually split one legal sentence into several testable checks (and merge others). The coverage matrix already hints at that; the registry still stays 1:1.

3. **Several product paths are unknown.** TLS config, app config, and postgres config are `<TO_BE_PROVIDED>`, so those evidence items fail closed. Filling the product profile would make the demo (and a lab scan) more complete.

4. **No live system yet.** The mock path is excellent for a safe demo and for tests. Until SSH (or an agent on the host) exists, this cannot assess a real NetBoss-XT instance.

5. **Asset mapping is keyword-based.** Fine for a UI story; not a substitute for owner-approved applicability per asset.

6. **Demo remediation is a fixture overlay.** That is the right safety model for a POC. Production needs change tickets, blast-radius, and an out-of-band apply path — still with re-scan as the only closer.

7. **No users, no audit identity store.** Approver names are typed in. Fine for a local demo; not fine for a regulated workflow.

8. **No severity, no score.** That is a deliberate POC choice. Stakeholders often want risk ranking. Add it only as an approved model, not as a hidden percentage.

9. **UI and CLI are aligned, but jobs are local.** Long runs are backgrounded in-process. A real deployment would need durable jobs and clearer run history across machines.

10. **Tests depend on PDFs being present for full Flow 1.** Document ingest is hard to CI without either committed fixtures or a checked-in extracted text corpus (with legal review).

What is already in good shape and worth emphasising:

- Hard split: collect vs decide vs remediate.
- Fail closed (missing evidence ≠ fail; unknown path ≠ guessed path).
- Hash-locked approved registry.
- Findings do not close because someone clicked Apply.
- Mock banner so nobody mistakes this for production evidence.

---

## Lines to use if questions get sharp

**“Is NetBoss-XT non-compliant?”**  
No. You are looking at a synthetic vulnerable fixture used to exercise the workflow.

**“Does a PASS mean we are CRA certified?”**  
No. It means the observed configuration matched the approved technical rules at collection time.

**“Can the AI change a verdict?”**  
No. Verdicts come from the rule engine. Models may only explain or suggest wording.

**“If we apply the fix in the UI, is the finding closed?”**  
No. Apply on demo only patches mock data in memory. Closure needs a new evidence run that returns PASS.

**“Why so many HUMAN_REVIEW controls?”**  
Because CRA Annex I includes process and manufacturer duties that a host scan cannot prove. The tool refuses to pretend it scanned them.

**“Can we point this at the lab tonight?”**  
Not with the current provider. The SSH target file is an example only. The contract is ready; the live collector is not.

---

## CLI equivalents (if someone asks)

```bash
nextboss-cra ingest
nextboss-cra validate-registry
nextboss-cra approve-registry --approver "Demo User" --version 1.0.0

nextboss-cra collect-evidence --target targets/nextboss-demo.mock.json --run-id RUN-DEMO-0001 --application router_monitor
nextboss-cra assess --run-id RUN-DEMO-0001
nextboss-cra remediate --run-id RUN-DEMO-0001

# Demo apply (TLS example), then prove closure
nextboss-cra propose-remediation --run-id RUN-DEMO-0001 --control-id NMS-CRA-0006
nextboss-cra approve-remediation --run-id RUN-DEMO-0001 --control-id NMS-CRA-0006 --approver "Demo User"
nextboss-cra apply-remediation --run-id RUN-DEMO-0001 --control-id NMS-CRA-0006
nextboss-cra collect-evidence --run-id RUN-DEMO-0002 --scenario vulnerable
nextboss-cra assess --run-id RUN-DEMO-0002
nextboss-cra verify --previous-run RUN-DEMO-0001 --new-run RUN-DEMO-0002
```

---

## Footer line (leave this on screen)

Automated technical readiness assessment of observed configuration.  
Not CRA certification. Not a statement of legal conformity.  
Today’s run uses synthetic / mock data.
