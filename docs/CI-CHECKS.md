# Athena SAST — CI checks capability

This is the scope for the CLI’s **CI checks** work. It answers what the
capability is, how it relates to ENG-74, and which AXI-856 / OWASP CI/CD
controls are v1 vs later.

The cheat-sheet link is the **standard we map to**, not the deliverable.

## Relationship to ENG-74

| Ticket | Owns | Does not own |
|--------|------|----------------|
| **This CLI work** | The `athena` binary, local OWASP gate, engine HTTP client, SARIF/JSON/JUnit, exit `0/1/2`, credential hygiene in the CLI, and the **definition of CI checks** | Marketplace listings, Jenkins plugin.xml, Azure extension packaging |
| **ENG-74** | Thin wrappers that **install + exec** this CLI (GitHub Action, Jenkinsfile, Azure YAML) | Scan logic, rule catalogs, engine calls |

ENG-74 is a **child of this CLI**, not a parallel scanner. Plugins contain
zero scan logic. If a check, token rule, or output format changes, it
changes here; wrappers only pass env and flags.

Treat ENG-74 as a linked/child issue. Do not duplicate “trigger a scan
from CI” as a second product.

## What “CI checks capability” means

### Which checks

Two depths, always labeled so we do not over-claim:

1. **Local OWASP CI/CD gate** (`athena scan` with no `--repo`, or
   `--modes pipeline`). Regex rules ATH001–ATH054 on the checkout.
   Findings are `source: local_owasp` and carry `owasp_id` CICD-SEC-1…10.
   This does **not** run OpenGrep / Trivy / KICS / Syft.
2. **Engine SAST** (when `ATHENA_API_URL` + `ATHENA_API_KEY` and `--repo`
   are set). CLI POSTs to product agents (code-review, secrets, IaC, SCA).
   Findings are `source: engine`.

Default CI command the plugins exec:

```text
athena scan --repo URL --branch BRANCH --target . \
  --modes code-review,secrets,iac,sca,pipeline \
  --format sarif --output athena-results.sarif \
  --json-output athena-results.json --fail-on high --quiet
```

Pair with `athena monitor` (same inputs) to record a snapshot without failing the build. Monitor POSTs `/scan/monitor-snapshot` when the engine is reachable; otherwise it prints `snapshot: local_only`. The engine `/ui` lists persisted snapshots (Mongo). G4 is [`.github/workflows/athena-engine.yml`](../.github/workflows/athena-engine.yml), off until `ATHENA_ENABLE_ENGINE=true` and the URL is **HTTPS** (or loopback on a self-hosted runner).

First-run wrappers omit `--repo` and use `--modes pipeline` (no API key).

The local gate **reads files**. It does not execute the target’s build
scripts, `postinstall` hooks, or IaC. That is the CLI-side PPE control
(CICD-SEC-4). Engine isolation for cloned third-party trees is an engine
design constraint (see v1 vs later).

### What triggers them

| Trigger | Typical event | Modes |
|---------|---------------|--------|
| `push` / `pull_request` (GitHub) | Every commit / PR against the default branches the workflow lists | `pipeline` first; full modes when engine secrets exist |
| Jenkins Pipeline from SCM | Each build | same |
| Azure pipeline `trigger` / `pr` | Each build | same |
| Laptop | Developer runs `athena scan` | local or full |

**Never** `pull_request_target` plus checkout of the PR head. That is the
GitHub “pwn request” pattern: secrets from the base repo are exposed to
attacker-controlled fork code. ATH042 flags it in *customer* YAML; our
wrappers must not use it.

### What the output is

| Artifact | Who consumes it |
|----------|-----------------|
| Exit `0` / `1` / `2` | The CI gate (frozen contract) |
| SARIF 2.1.0 (`sarif_source: cli_normalized`) | GitHub Code Scanning, Azure, GitLab |
| Athena JSON (`schema_version: 1.0`) | Humans, later correlation |
| JUnit (Jenkins) | Test Result trend |

The engine does **not** return SARIF. The CLI builds it.

## AXI-856 — token leak (compromised token, repo access)

We already lived this failure mode. Static master keys in CI are the same
shape. Scope below is **prevention in the CLI/plugins now**, detection on
the control plane later.

### v1 — non-negotiable before this ships

| Control | Where | What “done” means |
|---------|--------|-------------------|
| **No master key on argv** | CLI | No `--api-key` / `--token`. Auth is env-only (`ATHENA_API_KEY`, `ATHENA_REPO_TOKEN`). |
| **One action, one repo (contract)** | CLI + engine body | Every engine call includes `repository_url`. CI keys must be **scanner-role**, not admin. Do not share one key across orgs. Engine bind-to-repo is follow-up; the CLI already sends the repo so the bind is possible. |
| **Log redaction** | CLI + wrappers | CLI never prints secret values (errors, HTTP details, saved raw). Wrappers start with `set +x` / never `set -x`. QA item on every plugin change. |
| **Pwn-request warning** | Plugin docs + ATH042 | Documented; local gate fails customer YAML that combines `pull_request_target` + checkout. |
| **Pin our Action deps to SHA** | `action.yml`, workflows | `uses: …@<40-char SHA>` (CICD-SEC-8). Customers told to pin `ORG/athena-sast-cli@SHA`, never `@v1` / `@main`. |
| **Token prefix** | Docs + redaction | Prefer engine keys `ath_live_…` (already recognized by FastAPI tenancy). Distinct format so leak scanners and GitHub partner scanning can match later. |

### Later (not blocking CLI v1)

| Control | Why later |
|---------|-----------|
| **OIDC federation** instead of static `ATHENA_API_KEY` | Needs an engine token-exchange endpoint (GitHub Actions / Azure / Jenkins OIDC → short-lived Athena token). CLI will then accept the minted token the same way it accepts env today. |
| **Hard bind: key may only start a scan for repo X** | Engine/auth (Mongo key metadata). CLI already supplies the repo. |
| **Anomaly detection** (token that usually fires 1×/day from GitHub IPs now fires 200× from an unknown ASN) | Reuse ENG-58 behavioral baseline on the control plane, not in the CLI process. |
| **Canary tokens** (`ath_canary_…`) | Seed where leak-scanners look; any use is a breach. Engine + alerting. |
| **GitHub secret-scanning partner** | Register `ath_live_` / `ath_test_` / `ath_canary_`. One-time integration. |
| **First-use-from-new-location alerts** | Control plane, same idea as a bank card. |

## OWASP Top 10 CI/CD — two layers

Layer A: **scan the customer’s pipeline** (local rules).  
Layer B: **our own CLI/plugin supply chain**. The cheat sheet applies to
*us* as a vendor, not only to YAML we scan.

| ID | Customer scan (layer A) | Our pipeline (layer B) | v1 vs later |
|----|-------------------------|------------------------|-------------|
| **CICD-SEC-4 PPE** | ATH010–ATH019, ATH042 | CLI local gate is regex-only (no code execution). Engine must isolate clones (no `npm install` / `pip install` of the target, sandbox/cgroup for scanner CLIs). Retrofitting after CLI architecture is expensive — **design the engine sandbox now**; do not execute untrusted trees in the CLI. | v1: CLI does not exec target. Engine sandbox = engine ticket, linked. |
| **CICD-SEC-3 Dependency chain** | ATH047, ATH051, ATH054 | How we **distribute** the Action / Jenkinsfile / Azure YAML: pin this repo at a commit SHA; do not ask customers to `uses: …@main`. A compromised Athena plugin is a supply-chain hit on every customer (AXI-856 class). | v1: pin + docs. Signed releases / provenance = later. |
| **CICD-SEC-8 Ungoverned 3rd parties** | ATH041 (`@v1` / `@main` / `@latest`, not only `@latest`) | Our `action.yml` pins `github/codeql-action/upload-sarif` to a SHA. Same for `actions/checkout` and `setup-python` in example workflows. Document the tj-actions/changed-files failure mode for customers. | v1 |
| **CICD-SEC-6 Credential hygiene** | ATH001–ATH009, ATH040 | Env-only secrets, redaction, no `set -x`. | v1 |
| **CICD-SEC-5 PBAC** | ATH043, ATH048 | Action `permissions: contents: read` (+ `security-events: write` for SARIF). | v1 |
| **CICD-SEC-10 Logging** | ATH046 | Always upload SARIF/JSON/JUnit (`if: always()` / `post { always }`). | v1 |
| **CICD-SEC-9 Artifact signing** | ATH050–ATH053 | Sign CLI releases / SARIF later. One line in the spec is enough for v1. | later |
| **CICD-SEC-7 Runner hardening** | ATH020–ATH038, ATH045 | Guidance for self-hosted customers later. | later (docs line in v1) |
| **CICD-SEC-1 Flow control** | ATH044, ATH049 | Customers keep required reviews / environment gates. We do not auto-merge. | v1 scan; extra guidance later |
| **CICD-SEC-2 IAM** | ATH039, ATH043, ATH048 | Scanner-role keys, not org-admin. | v1 contract; engine bind later |

## Honesty

- Local “OWASP compliant” means **this regex gate found nothing**, not a
  certification.
- Token *scoping* in v1 is a **contract + request shape**. The engine
  still has a legacy env `API_KEY` that is a master key — do not put that
  key in customer CI. Use a scanner-role `ath_live_` key when tenancy is
  on; otherwise treat the env key as a lab-only secret.
- OIDC, canaries, partner scanning, and ASN anomaly detection are **not**
  implied by a green CI check.
