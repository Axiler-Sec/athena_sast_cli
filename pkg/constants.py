"""Athena CLI constants. Exit codes 0/1/2 are a frozen public contract."""

VERSION = "1.0.0"
TOOL_NAME = "athena"
OWASP_STANDARD = "CI/CD Security Cheat Sheet 2024"
OWASP_CHEATSHEET_URI = (
    "https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html"
)
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/"
    "master/Schemata/sarif-schema-2.1.0.json"
)
JSON_SCHEMA_VERSION = "1.0"

# Frozen forever. Never add a fourth code. Never change meanings.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

DEFAULT_HTTP_TIMEOUT = 600
DEFAULT_FAIL_ON = "high"
DEFAULT_FORMAT = "table"
DEFAULT_RAW_DIR = "athena-results/raw"

SEVERITY_ORDER = ("critical", "high", "medium", "low")
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

OWASP_RISKS = {
    "CICD-SEC-1": "Insufficient Flow Control Mechanisms",
    "CICD-SEC-2": "Inadequate Identity and Access Management",
    "CICD-SEC-3": "Dependency Chain Abuse",
    "CICD-SEC-4": "Poisoned Pipeline Execution (PPE)",
    "CICD-SEC-5": "Insufficient Pipeline-Based Access Controls (PBAC)",
    "CICD-SEC-6": "Insufficient Credential Hygiene",
    "CICD-SEC-7": "Insecure System Configuration",
    "CICD-SEC-8": "Ungoverned Usage of Third-Party Services",
    "CICD-SEC-9": "Improper Artifact Integrity Validation",
    "CICD-SEC-10": "Insufficient Logging and Visibility",
}

# athena owasp command: which local rules cover each risk (a rule may appear twice).
OWASP_RULE_COVERAGE = {
    "CICD-SEC-1": ["ATH044", "ATH049"],
    "CICD-SEC-2": ["ATH039", "ATH043", "ATH048"],
    "CICD-SEC-3": ["ATH047", "ATH051", "ATH054"],
    "CICD-SEC-4": [
        "ATH010", "ATH011", "ATH012", "ATH013", "ATH014", "ATH015",
        "ATH016", "ATH017", "ATH018", "ATH019", "ATH042",
    ],
    "CICD-SEC-5": ["ATH043"],
    "CICD-SEC-6": [
        "ATH001", "ATH002", "ATH003", "ATH004", "ATH005", "ATH006",
        "ATH007", "ATH008", "ATH009", "ATH040",
    ],
    "CICD-SEC-7": [
        "ATH020", "ATH021", "ATH022", "ATH023", "ATH024", "ATH025",
        "ATH026", "ATH027", "ATH028", "ATH029",
        "ATH030", "ATH031", "ATH032", "ATH033", "ATH034", "ATH035",
        "ATH036", "ATH037", "ATH038", "ATH045",
    ],
    "CICD-SEC-8": ["ATH041"],
    "CICD-SEC-9": ["ATH050", "ATH051", "ATH052", "ATH053"],
    "CICD-SEC-10": ["ATH046"],
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "vendor",
    "dist",
    "build",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
}

CODE_EXTS = {".py", ".js", ".ts", ".go", ".java", ".rb", ".sh"}
YAML_EXTS = {".yaml", ".yml"}
IAC_EXTS = {".tf"}
ENV_EXTS = {".env"}

ENGINE_ENDPOINTS = {
    "repo_verify": "/scan/verify-repository-contents",
    "repo_branches": "/scan/list-repository-branches",
    "image_verify": "/scan/verify-container-image",
    "image_tags": "/scan/list-container-image-tags",
    "code_review": "/scan/code-review-agent",
    "code_review_upload": "/scan/upload-code-review",
    "create_pr": "/scan/create-code-review-pr",
    "secrets": "/scan/secrets-agent",
    "secrets_upload": "/scan/upload-secrets",
    "iac": "/scan/iac-agent",
    "iac_upload": "/scan/upload-iac",
    "sca": "/scan/sca-agent",
    "sca_upload": "/scan/upload-sca",
    "sbom": "/scan/composition-analysis/sbom",
    "container": "/scan/container-agent",
    "container_review": "/scan/container-code-review",
    "apk": "/scan/apk-scan",
    "compliance": "/scan/compliance-mapper",
}
