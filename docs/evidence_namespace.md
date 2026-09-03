# Evidence namespace contract

Normalized evidence paths addressed by the deterministic evaluation rules in
the control registry. Flow 2 collectors must produce evidence objects whose
fields align with these paths, and the Flow 3 rule engine resolves rule paths
against them. Agent 2 neither produces nor addresses evidence.

This is an internal technical contract, not CRA legal text.

## TLS / certificates

| Path | Produced by | Meaning |
|------|-------------|---------|
| `tls_configuration.protocols.TLSv1_0` | Flow 2 collector | Whether TLS 1.0 is enabled (`true`/`false`) |
| `tls_configuration.protocols.TLSv1_1` | Flow 2 collector | Whether TLS 1.1 is enabled |
| `tls_configuration.cipher_suites` | Flow 2 collector | List or string of negotiated/configured cipher suites |
| `certificates.expired` | Flow 2 collector | Whether any in-scope certificate is expired |

The assessment layer recomputes `certificates.expired` from
`certificates.certificates[].expired` only when the collector did not supply it.
An observed value always wins over a derived one.

## Network exposure

| Path | Produced by | Meaning |
|------|-------------|---------|
| `open_ports.listeners` | Flow 2 collector | Observed listeners (`address`, `port`, `transport`, `process`) |
| `open_ports.ports` | Flow 2 collector | Sorted set of observed listening ports |
| `open_ports.unexpected_listeners` | downstream | Listeners on ports not in the expected set (list; empty when none) |

Expected ports for NetBoss-XT POC: `22`, `443`, `8443`, `5432` (from
`policy/security_assertions.yaml` → `network.expected_ports`).

Unexpected listeners are actioned as `REVIEW` unless a control requires FAIL.

`unexpected_listeners` is **derived downstream**, not collected. Deciding that a
listener is unexpected requires the policy expected-port set, and Flow 2 must
not load `policy/security_assertions.yaml`. The collector supplies the factual
`open_ports.listeners` input; the assessment layer computes the difference.

## SSH

| Path | Meaning |
|------|---------|
| `ssh_config.PermitRootLogin` | Effective `sshd_config` value |
| `ssh_config.PermitEmptyPasswords` | Effective `sshd_config` value |

Allowed values come from `policy/security_assertions.yaml` → `ssh.assertions`.

## File permissions

| Path | Meaning |
|------|---------|
| `file_permissions.world_writable` | Whether any in-scope security-sensitive config is world-writable |

## Accounts (legacy template)

| Path | Produced by | Meaning |
|------|-------------|---------|
| `local_users.accounts` | Flow 2 collector | Observed accounts (`username`, `uid`, `gid`, `shell`, `locked`, `has_password_hash`) |
| `local_users.default_accounts` | downstream | Presence of default/vendor accounts (unary `NOT_EXISTS` when absent) |

`default_accounts` is derived downstream for the same reason as
`unexpected_listeners`: identifying a vendor default account is a policy
judgement, not an observation. Password hashes are redacted at the MCP
boundary, so only their presence is recorded.

A name match alone is not treated as a finding. The account must also still be
usable, meaning not locked and without a non-login shell, so a disabled vendor
service account does not read as an exposed default credential. The name list
and the non-login shells are `DEFAULT_ACCOUNT_NAMES` and `NON_LOGIN_SHELLS` in
`src/config.py`. The path is omitted entirely when nothing matches, so the
approved `NOT_EXISTS` condition resolves as the registry intends.

## Who derives what

Derivation happens in `src/assessment/derive.py` during Flow 3, against an
in-memory copy of the normalized evidence. Evidence artifacts on disk are never
rewritten, so a derived value can never be mistaken later for a collected
observation. Each derived path is recorded in the assessment result under
`derived_paths` with the evidence item and the basis it came from.

A rule path is resolved only against evidence associated with the control that
requested it. Where one control holds several evidence items under the same
namespace root, for example TLS on both port 443 and port 8443, the condition
must hold for every one of them.

## Additional collected namespaces

Produced by Flow 2 for evidence and human review; no rule addresses them today.

| Path | Source tool |
|------|-------------|
| `system_info.*` | `get_system_info` |
| `local_groups.groups` | `get_groups` |
| `services.inventory`, `services.running` | `get_services` |
| `processes.inventory` | `get_processes` |
| `file.path`, `file.size_bytes`, `file.line_count` | `get_file` |
| `network_configuration.interfaces`, `.routes`, `.dns` | `get_network_configuration` |
| `firewall_rules.state`, `.enabled`, `.rules` | `get_firewall_rules` |
| `tls_configuration.reachable`, `.negotiated` | `get_tls_configuration` |
| `certificates.chain_complete`, `.certificates[]` | `get_certificates` |
| `installed_packages.inventory` | `get_installed_packages` |
| `security_logs.available`, `.logging_enabled`, `.entries` | `get_security_logs` |

## Notes for collectors

- Do not invent config file paths. If the product profile marks a path as
  `<TO_BE_PROVIDED>`, record evidence as unavailable / insufficient.
- Do not fail solely because an expected port (e.g. PostgreSQL `5432`) exists.
- Package inventory is evidence-only; do not claim vulnerability without an
  explicit vulnerability source.
