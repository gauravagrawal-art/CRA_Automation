"""Shared constants for Flow 1."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DOCUMENTS_DIR = PROJECT_ROOT / "documents"
AUTHORITATIVE_DIR = DOCUMENTS_DIR / "authoritative"
SUPPORTING_DIR = DOCUMENTS_DIR / "supporting"
REGISTRY_DIR = PROJECT_ROOT / "registry"
APPROVED_DIR = REGISTRY_DIR / "approved"
PROPOSALS_DIR = PROJECT_ROOT / "proposals"
PROMPTS_DIR = PROJECT_ROOT / "prompts"
PRODUCT_DIR = PROJECT_ROOT / "product"
POLICY_DIR = PROJECT_ROOT / "policy"
PRODUCT_PROFILE_PATH = PRODUCT_DIR / "nextboss_xt_product_profile.yaml"
SECURITY_ASSERTIONS_PATH = POLICY_DIR / "security_assertions.yaml"
TO_BE_PROVIDED = "<TO_BE_PROVIDED>"

PRODUCT_NAME = "NetBoss-XT"
PRODUCT_TYPE = "Network Management System"
CRA_CLASS = "I"
CRA_CATEGORY = "6"
CRA_CATEGORY_NAME = "Network Management Systems"

# User-facing applications in the Target Env. Internal mock scenarios
# (vulnerable / partial / compliant) remain a CLI/fixture concern.
APPLICATIONS: tuple[tuple[str, str], ...] = (
    ("router_monitor", "Router Monitor"),
    ("switch_monitor", "Switch Monitor"),
    ("sbc_monitor", "SBC Monitor"),
)
DEFAULT_APPLICATION_ID = "router_monitor"

EXPECTED_AUTHORITATIVE = [
    "CELEX_02024R2847-20241120_EN_TXT.pdf",
    "OJ_L_202502392_EN_TXT.pdf",
]

EXPECTED_SUPPORTING = [
    "C_2026_5252_CRA_Guidance.pdf",
    "ETSI_EN_304_621_V1.0.5.pdf",
    "C_2025_618_CRA_Standardisation_Request.pdf",
]

MCP_CAPABILITY_CATALOG = [
    "get_system_info",
    "get_users",
    "get_groups",
    "get_services",
    "get_open_ports",
    "get_processes",
    "get_file",
    "get_file_permissions",
    "get_network_configuration",
    "get_firewall_rules",
    "get_tls_configuration",
    "get_certificates",
    "get_installed_packages",
    "get_security_logs",
]

SCHEMA_VERSION = "1.1"
REGISTRY_VERSION = "0.1.0"

# --- Flow 2 (evidence collection) -------------------------------------------

EVIDENCE_DIR = PROJECT_ROOT / "evidence"
TARGETS_DIR = PROJECT_ROOT / "targets"
EVIDENCE_SCHEMA_VERSION = "2.0"

# Absolute paths the MCP file tools may read. Any path supplied by an approved
# control must still match one of these entries.
MCP_PATH_ALLOWLIST = [
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/*.conf",
    "/etc/os-release",
    "/etc/login.defs",
    "/etc/security/*.conf",
    "/etc/pki/tls/openssl.cnf",
    "/etc/firewalld/firewalld.conf",
    "/etc/postgresql/*/main/postgresql.conf",
    "/var/lib/pgsql/data/postgresql.conf",
    "/var/lib/pgsql/data/pg_hba.conf",
    "/opt/nextboss/conf/*.conf",
    "/opt/nextboss/conf/*.yaml",
]

# Hard caps enforced by the MCP layer before any payload is persisted.
MCP_MAX_OUTPUT_BYTES = 1_048_576  # 1 MiB per tool result
MCP_MAX_FILE_BYTES = 262_144  # 256 KiB per get_file read
MCP_MAX_LOG_ENTRIES = 500
MCP_MAX_LOG_TIME_RANGE_HOURS = 168  # 7 days

REDACTION_PLACEHOLDER = "[REDACTED]"

# Object keys whose values are always masked before persistence.
REDACTION_KEY_PATTERNS = [
    r"password",
    r"passwd",
    r"pass_hash",
    r"secret",
    r"token",
    r"api[_-]?key",
    r"private[_-]?key",
    r"credential",
    r"passphrase",
    r"shadow",
    r"auth[_-]?key",
]

# Value patterns masked wherever they appear in strings.
REDACTION_VALUE_PATTERNS = [
    r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+)?PRIVATE KEY-----",
    r"\$[0-9a-z]{1,2}\$[^\s:*!]{4,}",  # crypt(3) hashes: $6$..., $2b$...
    r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]{16,}=*",
    r"(?i)\b(?:aws_)?secret_access_key\s*[=:]\s*\S+",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"(?i)\bghp_[A-Za-z0-9]{20,}\b",
]

# Verdict vocabulary that must never appear in Flow 2 output.
FORBIDDEN_VERDICT_TOKENS = ["PASS", "FAIL", "PARTIAL", "COMPLIANT", "NON_COMPLIANT"]

# --- Flow 3 (assessment and reporting) --------------------------------------

ASSESSMENTS_DIR = PROJECT_ROOT / "assessments"
ASSESSMENT_SCHEMA_VERSION = "3.0"

# Input schema versions this assessment implementation can execute. An input
# outside these sets aborts preflight rather than being evaluated on guesswork.
SUPPORTED_EVIDENCE_SCHEMA_VERSIONS = {"2.0"}
SUPPORTED_REGISTRY_SCHEMA_VERSIONS = {"1.1"}

# Vendor/default account names for the derived local_users.default_accounts
# path. Naming an account "default" is a policy judgement rather than an
# observation, and it is kept here rather than in policy/security_assertions.yaml
# so the hashed Flow 1 policy input is unchanged. A name match alone is not a
# finding: the account must also still be usable (see NON_LOGIN_SHELLS).
DEFAULT_ACCOUNT_NAMES = [
    "admin",
    "administrator",
    "default",
    "guest",
    "nextboss",
    "operator",
    "pi",
    "support",
    "test",
    "ubuntu",
    "vagrant",
]

# Shells that mean an account cannot be logged into interactively.
NON_LOGIN_SHELLS = ["/sbin/nologin", "/usr/sbin/nologin", "/bin/false", "/usr/bin/false"]

# The POC has no approved severity/risk model, so every finding carries this.
DEFAULT_SEVERITY = "UNCLASSIFIED"

# --- Flow 4 (remediation, verification and finalization) --------------------

REMEDIATION_SCHEMA_VERSION = "4.0"
VERIFICATION_SCHEMA_VERSION = "4.0"

# Assessment documents this remediation implementation can read. An assessment
# outside this set aborts preflight rather than being interpreted on guesswork.
SUPPORTED_ASSESSMENT_SCHEMA_VERSIONS = {"3.0"}

# Flow 4 recommends; a system owner acts. No remediation item is ever executed.
REMEDIATION_OWNER = "SYSTEM_OWNER"

# --- Lifecycle overlay (mock remediation execution + human evidence review) ---

LIFECYCLE_SCHEMA_VERSION = "1.1"
SUPPORTED_LIFECYCLE_SCHEMA_VERSIONS = {"1.0", "1.1"}
# Soft cap for human-uploaded evidence attachments (bytes per file).
HUMAN_EVIDENCE_MAX_BYTES = 1_048_576

# Demo-target allow-listed execution (Flow 4 remediation actions).
DEMO_TARGET_ID = "nextboss-demo"
DEMO_PROVIDER = "mock"
DEMO_STATE_DIR = ASSESSMENTS_DIR / ".demo-state"
