# Athena SAST CLI

The Athena CLI is the backbone of CI plugins (Checkmarx model). Jenkins, GitHub Actions, and Azure DevOps install this binary and exec it. The CLI calls the Athena engine endpoints. The web UI is a **sibling** consumer of the same engine — it does not call this CLI.

## Two modes

**Local OWASP CI/CD gate** (no API key):

```bash
python3 athena.py scan tests/targets/bad_pipeline.yml
python3 athena.py owasp
```

This regex gate scans pipeline YAML, IaC, and source for [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) risks (CICD-SEC-1 through CICD-SEC-10). It is **not** as deep as the engine's OpenGrep / Trivy / KICS / Syft analysis. Findings are tagged `source: local_owasp`. What that capability is (checks, triggers, outputs) is spelled out in [docs/CI-CHECKS.md](docs/CI-CHECKS.md).

**Engine client** (requires env):

```bash
export ATHENA_API_URL="https://your-engine.example"
export ATHENA_API_KEY="..."          # never a CLI flag
export ATHENA_REPO_TOKEN="..."       # private repos
athena scan --repo https://github.com/org/app.git --branch main \
  --modes code-review,secrets,iac,sca,pipeline \
  --format sarif --output athena-results.sarif --fail-on high --quiet
```

Engine findings are tagged `source: engine`. Identifiers (CVE/CWE/CVSS) are passed through when the engine sends them and omitted when it does not.

## Honesty

- The engine product agents do **not** return SARIF. Athena builds SARIF 2.1.0 and labels it `sarif_source: cli_normalized`.
- `athena compliance` prints **mapped controls**, not a certification.
- Exit codes are a frozen contract: `0` clean, `1` findings at/above `--fail-on`, `2` tool/auth/config error.
- `athena monitor` is the Snyk-monitor analogue: same scan, never exit 1. The engine dashboard at `/ui` lists those snapshots when Mongo is configured. It is **not** a live Snyk org graph. Without Mongo, `snapshot: local_only`.

## Install

```bash
cd athena-sast-cli
python3 -m pip install pytest   # when pip is available
python3 athena.py version
python3 -m unittest discover -s tests -v
```

## Docker (no secrets in the image)

```bash
docker build -t athena-sast-cli .
docker run --rm -e ATHENA_API_URL -e ATHENA_API_KEY -v "$PWD":/src -w /src \
  athena-sast-cli scan --target . --modes pipeline
```

Runtime env only. Do not `COPY .env`.

## Cursor MCP (this machine only)

Copy [`.cursor/mcp.json.example`](.cursor/mcp.json.example) into a local MCP config. `athena mcp` is **stdio** — not a port on the engine ALB. Tool text is redacted. There is no generated second Python SDK (`pkg/client.py` is the client).

## GitHub: local gate vs engine

- [`.github/workflows/athena.yml`](.github/workflows/athena.yml) — always-on local OWASP gate (`modes: pipeline`). No engine secrets.
- [`.github/workflows/athena-engine.yml`](.github/workflows/athena-engine.yml) — Snyk-like engine job. Off until repo variable `ATHENA_ENABLE_ENGINE=true`. Needs `https://` `ATHENA_API_URL` (you attach ACM + DNS). Public `http://` is refused. Dashboard: engine `/ui` (snapshots).

## Product documentation

Full operator manual (Checkmarx-style hub: overview, architecture, CLI, engine routes, GitHub / Jenkins / Azure):

- **[docs/athena-sast.html](docs/athena-sast.html)** — open in a browser (sidebar + print to PDF)
- **[docs/Athena-SAST-Documentation.docx](docs/Athena-SAST-Documentation.docx)** — Word
- **[docs/CI.md](docs/CI.md)** — numbered checkpoints (laptop → engine → G/J/A wrappers)
- **[docs/CI-CHECKS.md](docs/CI-CHECKS.md)** — what “CI checks” means, ENG-74 split, AXI-856 / OWASP v1 vs later

## Start here if you are new

Open **[docs/CI.md](docs/CI.md)** and follow it **top to bottom**:

1. Laptop scan (no password) — Steps 1–7  
2. Connect to the engine (admin) — Steps 8–13  
3. GitHub wrapper — G0–G3. Jenkins — J0–J3. Azure — A0–A3. Engine secrets are G4 / J4 / A4 only.

Plugins contain **zero** scan logic. Token scoping and log redaction for those wrappers are specified in **[docs/CI-CHECKS.md](docs/CI-CHECKS.md)** (v1 vs later; ENG-74 is the plugin child of this CLI).

## License

Apache-2.0
