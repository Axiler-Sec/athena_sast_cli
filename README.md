# Athena SAST CLI

Installable client for Athena SAST. Local scans need no engine. Engine scans use environment variables only.

Never pass `ATHENA_API_KEY` as a flag. Never commit `.env`.

## Install

### pip

```bash
pip install athena-sast
export ATHENA_API_URL="https://YOUR_ENGINE"
export ATHENA_API_KEY="..."
athena scan --repo https://github.com/ORG/APP.git --branch main --fail-on high
```

`ATHENA_API_URL` is required for engine scans. It is not hardcoded. Do not put the engine hostname in this repository, issues, or examples.

### GitHub Release binary

Download `athena-<version>-linux-x64` (or `macos-arm64` / `windows-x64.exe`) and `SHA256SUMS` from [Releases](https://github.com/Axiler-Sec/athena_sast_cli/releases).

```bash
chmod +x athena-*-linux-x64
export ATHENA_API_URL="https://YOUR_ENGINE"
export ATHENA_API_KEY="..."
./athena-*-linux-x64 scan --repo https://github.com/ORG/APP.git --branch main --fail-on high
```

### Docker

```bash
docker run --rm \
  -e ATHENA_API_URL \
  -e ATHENA_API_KEY \
  -v "$PWD":/src -w /src \
  ghcr.io/axiler-sec/athena-sast-cli \
  scan --repo https://github.com/ORG/APP.git --branch main --fail-on high
```

### GitHub Action

Copy [`examples/github-workflow.yml`](examples/github-workflow.yml), or:

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

Put secrets on the job `env`. Use `pull_request`, not a privileged fork-PR event. Pin a tag or a 40-character SHA, not `@main`. See [SECURITY.md](SECURITY.md).

## Commands

Local (no API key):

```bash
athena scan tests/targets/bad_pipeline.yml
athena owasp
```

Engine (requires env):

```bash
export ATHENA_API_URL="https://YOUR_ENGINE"
export ATHENA_API_KEY="..."
export ATHENA_REPO_TOKEN="..."   # private repos
athena scan --repo https://github.com/ORG/APP.git --branch main \
  --modes code-review,secrets,iac,sca,pipeline \
  --format sarif --output athena-results.sarif --fail-on high --quiet
```

Exit codes: `0` clean, `1` findings at or above `--fail-on`, `2` tool/auth/config error.

`athena monitor` records the same scan and never exits `1`. Exit `2` still means the tool did not run.

`athena compliance` prints mapped controls, not a certification.

## Develop from source

```bash
python3 -m pip install pytest
python3 athena.py version
python3 -m unittest discover -s tests -v
```

## License

Apache-2.0
