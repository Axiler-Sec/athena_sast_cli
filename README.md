# Athena SAST CLI

The Athena CLI is the backbone of CI plugins (Checkmarx model). Jenkins, GitHub Actions, and Azure DevOps install this binary and exec it. The CLI calls the Athena engine endpoints. The web UI is a **sibling** consumer of the same engine — it does not call this CLI.

## Two modes

**Local OWASP CI/CD gate** (no API key):

```bash
python3 athena.py scan tests/targets/bad_pipeline.yml
python3 athena.py owasp
```

This regex gate scans pipeline YAML, IaC, and source for [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) risks (CICD-SEC-1 through CICD-SEC-10). It is **not** as deep as the engine's OpenGrep / Trivy / KICS / Syft analysis. Findings are tagged `source: local_owasp`.

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

## Install

```bash
cd athena-sast-cli
python3 -m pip install pytest   # when pip is available
python3 athena.py version
python3 -m unittest discover -s tests -v
```

## Product documentation

Full operator manual (Checkmarx-style hub: overview, architecture, CLI, engine routes, GitHub / Jenkins / Azure):

- **[docs/athena-sast.html](docs/athena-sast.html)** — open in a browser (sidebar + print to PDF)
- **[docs/Athena-SAST-Documentation.docx](docs/Athena-SAST-Documentation.docx)** — Word
- **[docs/CI.md](docs/CI.md)** — numbered checkpoints (laptop → engine → G/J/A wrappers)

## Start here if you are new

Open **[docs/CI.md](docs/CI.md)** and follow it **top to bottom**:

1. Laptop scan (no password) — Steps 1–7  
2. Connect to the engine (admin) — Steps 8–13  
3. GitHub wrapper — G0–G3. Jenkins — J0–J3. Azure — A0–A3. Engine secrets are G4 / J4 / A4 only.

Plugins contain **zero** scan logic.

## License

Apache-2.0
