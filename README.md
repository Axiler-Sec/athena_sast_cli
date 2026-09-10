# Athena SAST CLI

Client for the Athena engine plus a local OWASP CI/CD gate. The engine stays separate; this repo is the public install surface (PyPI, GitHub Releases, GHCR, GitHub Action).

Auth is environment-only. Never pass `ATHENA_API_KEY` as a flag. Never commit `.env`.

## Install

### pip (PyPI)

```bash
pip install athena-sast
export ATHENA_API_URL="https://YOUR_ENGINE"
export ATHENA_API_KEY="..."   # never a flag
athena scan --repo https://github.com/ORG/APP.git --branch main --fail-on high
```

`ATHENA_API_URL` is required for engine scans. Set it in the environment (or a secret store). It is **not** hardcoded in the CLI. Do not put the engine hostname in this repo, issues, or examples.

### GitHub Release binary

Download `athena-<version>-linux-x64` (or `macos-arm64` / `windows-x64.exe`) and `SHA256SUMS` from [Releases](https://github.com/Axiler-Sec/athena_sast_cli/releases).

```bash
chmod +x athena-*-linux-x64
export ATHENA_API_URL="https://YOUR_ENGINE"
export ATHENA_API_KEY="..."
./athena-*-linux-x64 scan --repo https://github.com/ORG/APP.git --branch main --fail-on high
```

### Docker (GHCR)

Runtime env only. The image does not contain keys.

```bash
docker run --rm \
  -e ATHENA_API_URL \
  -e ATHENA_API_KEY \
  -v "$PWD":/src -w /src \
  ghcr.io/axiler-sec/athena-sast-cli \
  scan --repo https://github.com/ORG/APP.git --branch main --fail-on high
```

### GitHub Action

This repo is the Action. Customers copy YAML from [`examples/github-workflow.yml`](examples/github-workflow.yml) (works via [PyPI](https://pypi.org/project/athena-sast/1.1.1/) from any repo).

**Marketplace / `uses:` form** (repo must be **public**; pin a tag or a 40-character SHA, not `@main`):

```yaml
name: Athena SAST
on:
  pull_request:
  push:
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    env:
      ATHENA_API_URL: ${{ secrets.ATHENA_API_URL }}
      ATHENA_API_KEY: ${{ secrets.ATHENA_API_KEY }}
    steps:
      - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5.1.0
        with:
          persist-credentials: false
      - uses: Axiler-Sec/athena_sast_cli@v1.1.1
        with:
          repo: https://github.com/${{ github.repository }}.git
          branch: ${{ github.ref_name }}
          fail-on: high
```

Composite actions cannot read `secrets.*`; put them on the job `env:`. Use `pull_request`, never the privileged fork-PR event with a checkout of the PR head. See [SECURITY.md](SECURITY.md).

Local gate only (no engine secrets): omit `repo` / unset `ATHENA_API_KEY` and use `modes: pipeline`. Do not put `localhost` in a GitHub secret.

GitHub Marketplace listing requires this repository to be **public**, then a release with **Publish this Action to the GitHub Marketplace** checked. Docs: [Publishing actions in GitHub Marketplace](https://docs.github.com/en/actions/how-tos/create-and-publish-actions/publish-in-github-marketplace).

## Two modes

**Local OWASP CI/CD gate** (no API key):

```bash
athena scan tests/targets/bad_pipeline.yml
athena owasp
```

This regex gate scans pipeline YAML, IaC, and source for [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) risks (CICD-SEC-1 through CICD-SEC-10). It is **not** as deep as the engine's OpenGrep / Trivy / KICS / Syft analysis. Findings are tagged `source: local_owasp`.

**Engine client** (requires env):

```bash
export ATHENA_API_URL="https://YOUR_ENGINE"
export ATHENA_API_KEY="..."          # never a CLI flag
export ATHENA_REPO_TOKEN="..."       # private repos
athena scan --repo https://github.com/ORG/APP.git --branch main \
  --modes code-review,secrets,iac,sca,pipeline \
  --format sarif --output athena-results.sarif --fail-on high --quiet
```

Engine findings are tagged `source: engine`. Identifiers (CVE/CWE/CVSS) are passed through when the engine sends them and omitted when it does not.

## Honesty

- The engine product agents do **not** return SARIF. Athena builds SARIF 2.1.0 and labels it `sarif_source: cli_normalized`.
- `athena compliance` prints **mapped controls**, not a certification.
- Exit codes are a frozen contract: `0` clean, `1` findings at/above `--fail-on`, `2` tool/auth/config error.
- `athena monitor` records a snapshot: same scan, never exit 1. Without Mongo, `snapshot: local_only`.

## Develop from source

```bash
cd athena-sast-cli
python3 -m pip install pytest
python3 athena.py version
python3 -m unittest discover -s tests -v
```

## Cursor MCP (this machine only)

Copy [`examples/mcp.json.example`](examples/mcp.json.example) into a local MCP config. `athena mcp` is **stdio** — not a network service. Tool text is redacted.

## Product documentation

- **[SECURITY.md](SECURITY.md)** — reporting and secret handling

## License

Apache-2.0
