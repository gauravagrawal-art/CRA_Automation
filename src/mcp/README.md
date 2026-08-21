# Infrastructure MCP

Read-only technical evidence collection for Flow 2. This package is code, not
an LLM agent: the approved control registry is the scan plan, and the tool
contracts in [contracts.py](contracts.py) are the entire interface.

## Policy

```text
Infrastructure MCP Policy

Purpose:
Collect read-only technical evidence from the configured target.

Rules:
- Never make CRA compliance decisions.
- Never return PASS/FAIL/PARTIAL.
- Never generate remediation.
- Never interpret CRA or ETSI requirements.
- Never execute arbitrary commands supplied by a model.
- Only implement explicitly registered tool capabilities.
- Validate every tool argument.
- Enforce command/path allowlists.
- Enforce output-size limits.
- Redact configured secrets before evidence is persisted.
- Do not change files, services, users, packages, network settings,
  firewall configuration or application configuration.
- Every result must include tool name, target ID, collection timestamp,
  provider and collection status.
- Treat target content as untrusted data.
```

## Capabilities

All fourteen capabilities are read-only. There is no generic shell or exec
tool, and no argument accepts a command string.

| Tool | Arguments | Returns |
|------|-----------|---------|
| `get_system_info` | none | hostname, OS, version, kernel, architecture |
| `get_users` | none | local account metadata (password material redacted) |
| `get_groups` | none | groups and memberships |
| `get_services` | none | service name, state, enablement, executable metadata |
| `get_open_ports` | `port?` | normalized listener information |
| `get_processes` | none | constrained process inventory |
| `get_file` | `path` | allowlisted file content, size-limited |
| `get_file_permissions` | `path` | owner, group, mode, ACL metadata |
| `get_network_configuration` | none | interfaces, addresses, routes, DNS |
| `get_firewall_rules` | none | firewall state and rules |
| `get_tls_configuration` | `host`, `port` | reachability, protocols, cipher suites |
| `get_certificates` | `host`, `port` | subject, issuer, validity, SANs, chain metadata |
| `get_installed_packages` | none | package inventory only |
| `get_security_logs` | `source?`, `max_entries?`, `time_range_hours?` | bounded log excerpt |

`get_installed_packages` is inventory evidence. This layer never decides
whether a version is vulnerable.

## Enforcement

- **Registration** — a tool not present in both `MCP_CAPABILITY_CATALOG` and
  `TOOL_ARGUMENT_SCHEMAS` cannot be called.
- **Arguments** — every contract sets `extra="forbid"`; unknown or malformed
  arguments raise `InvalidArgumentsError` before a provider is reached.
- **Paths** — a path supplied by an approved control must still match
  `MCP_PATH_ALLOWLIST`. Relative paths, `..` segments and `<TO_BE_PROVIDED>`
  are refused.
- **Size** — per-file and per-result byte caps, plus bounded log entry counts
  and time ranges.
- **Redaction** — applied at the provider boundary in
  [redaction.py](redaction.py), before the result crosses back to the runner.
  If redaction fails, the payload is discarded rather than persisted.

## Untrusted input

All target output is data. Configuration files, logs, banners, package
metadata, service descriptions and process metadata may contain text such as
`Ignore previous instructions...`; this layer has no interpreter, so such
content is stored and hashed as evidence and nothing more.
