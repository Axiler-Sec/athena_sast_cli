# Athena CLI — teach-me walkthrough (admin and users)

If you have never set up a SAST tool in CI, start here. Read **in order**. Each step says what to type, **why**, and **what “good” looks like**.

There are two jobs:

- **You as a user/developer** — run a scan on your laptop, then copy a pipeline file into a repo.
- **You as an admin** — keep the engine running, create the API key, put secrets in GitHub/Jenkins/Azure so developers never see them.

You can be both people. Do the laptop steps first. CI comes later.

---

## Picture in your head (30 seconds)

```
You (laptop or CI)
   →  Athena CLI  (the `athena` / `python3 athena.py` command)
         →  either scans files on disk (local OWASP gate, no password)
         →  or calls your FastAPI engine (needs URL + API key)
                →  OpenGrep, Trivy, KICS, Syft, …
```

The **web UI** also talks to the FastAPI engine. The UI does **not** run this CLI. Jenkins / GitHub / Azure do **not** call the engine themselves — they only run the CLI.

**Golden rule:** passwords and API keys go in **environment variables** or a **secret store**. Never `athena --api-key ....` (that would land in shell history). Never `set -x` in a plugin script (tokens land in plaintext build logs).

What “CI checks” means (which checks, triggers, outputs), how this CLI relates to **ENG-74**, and AXI-856 / OWASP v1 vs later: **[CI-CHECKS.md](CI-CHECKS.md)**.

Snyk pairing: `athena monitor` records a snapshot and **never fails on findings**. `athena scan --fail-on high` is the gate. Engine-from-CI (G4) stays off until the engine has a **private, reachable, HTTPS** URL — GitHub-hosted runners cannot use `http://127.0.0.1:8012`, and a public `http://` ALB would send `ATHENA_API_KEY` in cleartext.

---

# Part 1 — User: try it on your laptop (no CI, no engine)

**Goal:** see a real scan, a real exit code, and a real findings list.

## Step 1 — Open a terminal in the CLI folder

```bash
cd /home/sh/Desktop/athena_sast/athena-sast-cli
```

**Why:** every command below assumes this folder is your current directory (`athena.py` lives here).

**Good:** `ls athena.py` prints `athena.py`.

---

## Step 2 — Ask the CLI who it is

```bash
python3 athena.py version
```

**Why:** if this fails, Python is missing or you are in the wrong folder. Fix that before anything else.

**Good:** a line like `Athena SAST v1.0.0`.

**If it fails:** install Python 3.10+ (`python3 --version`). Stay in `athena-sast-cli`.

---

## Step 3 — See the 10 OWASP CI/CD risks this tool covers

```bash
python3 athena.py owasp
```

**Why:** Athena is not only “scan Python for SQL injection”. It also checks **pipeline YAML** against the [OWASP CI/CD Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/CI_CD_Security_Cheat_Sheet.html) (unpinned Actions, secrets in `env:`, and so on).

**Good:** you see `CICD-SEC-1` through `CICD-SEC-10` with rule IDs.

---

## Step 4 — Scan a file that is *supposed* to be dirty

```bash
python3 athena.py scan tests/targets/bad_pipeline.yml --format table
echo "Exit code was: $?"
```

**Why:** `bad_pipeline.yml` is a fake insecure GitHub workflow (secret in `env`, action `@latest`, unpinned `pip install`). You are proving the **local gate** works. **No API key. No network.**

**Good:**

- The table lists rules such as `ATH040`, `ATH041`, `ATH047`.
- `Exit code was: 1` — **1 means “scan worked, but findings are at/above the fail threshold.”** That is a failed build in CI. It is not a crash.

**Exit codes (memorize these three):**

| Code | Meaning | CI color |
|------|---------|----------|
| **0** | Scan finished. Nothing at/above `--fail-on`. | Green |
| **1** | Scan finished. Findings at/above `--fail-on`. | Red (policy) |
| **2** | Scan **did not run** (bad path, missing key, engine down). | Red (broken tool) |

---

## Step 5 — Scan a file that is *supposed* to be clean

```bash
python3 athena.py scan tests/targets/clean_app.py --fail-on low --format table
echo "Exit code was: $?"
```

**Why:** `--fail-on low` is the strictest gate (even Low findings fail). A clean file must still exit **0**.

**Good:** `No findings. Pipeline is OWASP CI/CD compliant.` and exit `0`.

(“Compliant” here only means **this local regex gate found nothing**. It is not a legal SOC 2 certificate.)

---

## Step 6 — Prove a missing path is exit 2 (tool error)

```bash
python3 athena.py scan /this/path/does/not/exist
echo "Exit code was: $?"
```

**Good:** a message that the target does not exist, exit **2**.

---

## Step 7 — Write SARIF to a file (what GitHub reads)

```bash
python3 athena.py scan tests/targets/bad_python.py --format sarif --output /tmp/athena-results.sarif
python3 -c "import json; d=json.load(open('/tmp/athena-results.sarif')); print(d['runs'][0]['properties'])"
```

**Why:** GitHub Code Scanning, Azure, and GitLab ingest **SARIF**. Your engine does **not** return SARIF. The CLI **builds** SARIF and stamps `sarif_source: cli_normalized`. Always write SARIF to a **file** in CI (`--output`), do not only print it.

**Good:** you see `'sarif_source': 'cli_normalized'`.

You now know the user laptop path. Next is connecting to the **engine** (real OpenGrep/Trivy). That needs an admin (or you wearing the admin hat).

---

# Part 2 — Admin: connect the CLI to the FastAPI engine

**Goal:** `ATHENA_API_URL` + `ATHENA_API_KEY` so `athena code-review` can call `POST /scan/code-review-agent`.

## Step 8 — Understand the two different passwords

People mix these up. They are **not** the same:

| Name | Lives where | What it unlocks |
|------|-------------|-----------------|
| **Engine API key** | FastAPI `.env` as `API_KEY=...` | Permission to call `/scan/...`. CLI env name: **`ATHENA_API_KEY`**. Header: `X-API-Key`. |
| **Git token** | GitHub/GitLab personal or `GITHUB_TOKEN` | Permission for the **engine** to clone a **private** repo. CLI env name: **`ATHENA_REPO_TOKEN`**. |

Public GitHub repos often need **only** the API key. Private repos need both.

---

## Step 9 — Confirm the engine is up

If you already run the scanner locally (Docker Compose / uvicorn):

```bash
curl -sS -H "X-API-Key: YOUR_KEY_HERE" http://127.0.0.1:8000/health
```

Replace `YOUR_KEY_HERE` with the same value as `API_KEY` in `athena-sast-scanner-fastapi/.env`.

**Why:** if health fails, the CLI will always exit **2** (`engine unreachable` or `auth failed`). Fix the engine before you debug the CLI.

**Good:** JSON with a healthy status, HTTP 200.

**If you deploy on Fargate:** use the ALB URL from CloudFormation (`ScannerApiUrl`), not `localhost`.

---

## Step 10 — Export env vars in **this** terminal (laptop test)

```bash
# same folder as athena.py
export ATHENA_API_URL="http://127.0.0.1:8000"    # no trailing slash
export ATHENA_API_KEY="paste-the-same-value-as-API_KEY"
# only if the git repo is private:
# export ATHENA_REPO_TOKEN="ghp_...."
```

**Why `export`:** the CLI reads the environment. Closing the terminal clears it. That is good — the key is not saved in `athena.yaml`.

**Check they are set (does not print the full key):**

```bash
echo "URL=$ATHENA_API_URL"
echo "KEY is set? $( [ -n \"$ATHENA_API_KEY\" ] && echo yes || echo NO )"
```

**Never:**

```bash
python3 athena.py scan --api-key secret   # this flag does not exist on purpose
```

---

## Step 11 — Pre-flight: can the engine see the repo?

Pick a **public** repo first (easier):

```bash
python3 athena.py repo verify \
  --repo https://github.com/octocat/Hello-World.git \
  --branch master \
  --format json
```

**Why:** `verify` is a cheap call (`POST /scan/verify-repository-contents`). If the URL, branch, or token is wrong, you fail in seconds instead of after a 10-minute scan.

**Good:** JSON with `"verified": true`.  
**Bad:** exit 2, `auth failed` → key/URL wrong. `verified: false` → repo/branch/token.

List branches if you are unsure of the name:

```bash
python3 athena.py repo branches --repo https://github.com/octocat/Hello-World.git --format json
```

---

## Step 12 — Run one real engine scan (code review only)

Agents are slow (minutes). Default HTTP timeout is **600 seconds**. Do not use a 30-second timeout.

```bash
python3 athena.py code-review \
  --repo https://github.com/octocat/Hello-World.git \
  --branch master \
  --format json \
  --fail-on critical
```

**Why `--fail-on critical`:** you are testing connectivity, not failing the build on every High finding yet.

**Good:** JSON with `"tool": "athena"` and `"source": "engine"` on findings (or zero findings).  
**Bad:** exit 2 — read the stderr line (`ATHENA_API_KEY is not set`, `auth failed`, `engine unreachable`).

Raw engine JSON is also saved under `athena-results/raw/` **before** parse (so a crash still leaves a file to debug).

---

## Step 13 — Full CI-style command (what plugins will run)

```bash
python3 athena.py scan \
  --repo https://github.com/YOUR_ORG/YOUR_APP.git \
  --branch main \
  --target . \
  --modes code-review,secrets,iac,sca,pipeline \
  --format sarif \
  --output athena-results.sarif \
  --json-output athena-results.json \
  --fail-on high \
  --quiet
echo "Exit: $?"
```

**What this does, in order:**

1. `repo verify`
2. Engine: code-review, secrets, iac, sca (one after another)
3. Local pipeline YAML scan of `--target` (the checkout)
4. Merge findings, write SARIF + JSON files
5. Exit `0` or `1` from `--fail-on high` (Critical or High fail the build; Medium/Low do not)

`--quiet` hides progress chatter. Files still get written.

---

# Part 3 — Wrappers (one at a time)

A **wrapper** is not a second scanner. GitHub / Jenkins / Azure only install `athena` and run the **same command** you already ran on the laptop.

**Rule:** finish one checkpoint (see “Good”) before you start the next. GitHub first (G0–G3), then Jenkins (J0–J3), then Azure (A0–A3). Do **not** put `http://127.0.0.1:8012` in any cloud secret store.

Order: **GitHub first** → Jenkins → Azure.

---

## Wrapper 1 of 3 — GitHub Actions

**Pwn request (CICD-SEC-4):** do **not** use `on: pull_request_target` and then `actions/checkout` of the PR head. That exposes `ATHENA_API_KEY` / `ATHENA_REPO_TOKEN` to a fork PR (AXI-856 class). Use `pull_request` or `push`. The local gate flags the bad pattern as ATH042.

**CICD-SEC-8:** pin third-party actions (and this CLI, if it is a separate repo) to a **40-character commit SHA**. `@v1` / `@main` is how tj-actions/changed-files was hijacked. ATH041 flags mutable tags in *customer* YAML; our examples must pin too.

### Checkpoint G0 — engine still up? (do this before any YAML)

In a terminal:

```bash
curl -sS -m 5 http://127.0.0.1:8012/health
cd /home/sh/Desktop/athena_sast/athena-sast-cli
python3 athena.py version
```

**Good:** health JSON includes `"status":"healthy"`. Version prints `Athena SAST v1.0.0`.  
**Bad:** curl fails → start the engine (`docker compose up -d` in `athena-sast-scanner-fastapi`). Do not continue.

---

### Checkpoint G1 — run the *exact* command the GitHub action will run (laptop)

The plugin does **not** contain scan logic. It execs this. Prove it on your machine **before** GitHub exists:

```bash
cd /home/sh/Desktop/athena_sast/athena-sast-cli
python3 athena.py scan \
  --target . \
  --modes pipeline \
  --format sarif \
  --output /tmp/athena-wrapper-check.sarif \
  --json-output /tmp/athena-wrapper-check.json \
  --fail-on high \
  --quiet
echo "Exit: $?"
python3 -c "import json; d=json.load(open('/tmp/athena-wrapper-check.sarif')); print(d['runs'][0]['properties'])"
```

**Why `--modes pipeline` only:** this checkpoint proves files + exit codes. It does **not** need GitHub.com to reach your laptop engine.

**Good:**

- Exit is **1** on this CLI repo (findings in workflow YAML) **or** **0** if you pointed `--target` at a clean folder.
- `/tmp/athena-wrapper-check.sarif` exists.
- Print includes `'sarif_source': 'cli_normalized'`.

**Bad:** exit **2** → stop. Fix the CLI/path. Do not open GitHub yet.

---

### Checkpoint G2 — understand this trap (read, do not click yet)

GitHub’s machines are in the cloud. They **cannot** call `http://127.0.0.1:8012` on your PC.

So the **first** GitHub workflow must be **local gate only** (no `repo:` input, no API secrets). That still tests: checkout → install CLI → `athena scan` → SARIF file.

Engine-from-GitHub is Checkpoint G4, only after this repo is on GitHub **and** the engine URL is reachable from GitHub **without sending the API key in cleartext** (HTTPS, or a self-hosted runner on the engine network — not a public `http://` ALB).

**Good:** you can say out loud: “localhost is my laptop; GitHub Actions is a different computer.”  
If that is unclear, do not create secrets yet.

---

### Checkpoint G3 — first workflow (local gate, no secrets)

Only after G1 is Good.

1. This folder must be a **GitHub repository** (or live inside one). If it is not on GitHub yet: create a repo, `git init` / remote / push. Ask if you have never done that.
2. This repo already contains [`.github/workflows/athena.yml`](../.github/workflows/athena.yml) (local gate, `uses: ./`, `modes: pipeline`, no secrets). If you are copying into another app repo, use **exactly** this file:

```yaml
name: Athena SAST
on:
  push:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  athena:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5.6.0
        with:
          python-version: "3.12"
      - uses: ./
        with:
          target: '.'
          fail-on: high
          modes: pipeline
      - name: Athena monitor (record; does not gate on findings)
        if: always()
        run: |
          set +x
          python3 -m pip install --quiet "${GITHUB_WORKSPACE}"
          athena monitor --target . --modes pipeline --quiet
```

`uses: ./` means “the `action.yml` in **this** repo root”. If the GitHub repo is the parent `athena_sast` folder, use `uses: ./athena-sast-cli` instead.

3. Commit and push. GitHub → **Actions** tab → run named **Athena SAST**.

**Good:**

- Job ran. Scan step exit **0** or **1** (1 = findings; still a working tool).
- A file `athena-results.sarif` was produced (open the job logs / artifacts).
- You did **not** need `ATHENA_API_KEY`.
- The **Athena monitor** step ran (`if: always()`). It does not fail the job on findings.

**Stop here for GitHub.** Next is Jenkins (J0), then Azure (A0). Do not add engine secrets until G3 is Good. Do not put localhost in secrets. G4 needs a URL GitHub can reach **over HTTPS** (or a self-hosted runner). A public HTTP ALB is not acceptable.

**Bad:**

- “Unable to resolve action” → `uses:` path is wrong.
- pip / python error → `setup-python` missing.
- Exit **2** → read the scan step log; do not add secrets to “fix” it.

---

### Checkpoint G4 — engine from GitHub (only if G3 passed **and** the engine URL is reachable **without cleartext keys**)

Keep [`.github/workflows/athena.yml`](../.github/workflows/athena.yml) as the **local pipeline gate**. Do not put engine secrets there.

Skip G4 while the engine is only `http://127.0.0.1:8012`. GitHub-hosted runners cannot reach your laptop. A public `http://` ALB is also a blocker: `ATHENA_API_KEY` would travel in the clear.

**You attach DNS + ACM** (this repo does not mint a certificate):

1. Custom domain pointing at the Fargate ALB.
2. ACM certificate in the **ALB region**; `.env` `ACM_CERTIFICATE_ARN` + `PUBLIC_HOSTNAME`.
3. Prove `curl -sS -H "X-API-Key: …" https://YOUR_HOST/health` returns 200. Until that works, do not claim GitHub talks to the engine.

Then:

1. Repo **Settings** → **Secrets and variables** → **Actions** → secrets:

| Name (exact) | Value |
|--------------|--------|
| `ATHENA_API_URL` | `https://YOUR_HOST` — **no** trailing `/`. Never a public `http://` ALB. Loopback `http://127.0.0.1:8012` only on a **self-hosted** runner. |
| `ATHENA_API_KEY` | same value as FastAPI `API_KEY` |

2. Same page → **Variables** → `ATHENA_ENABLE_ENGINE` = `true`. That turns on [`.github/workflows/athena-engine.yml`](../.github/workflows/athena-engine.yml). The job refuses public `http://` URLs before it sends the key.
3. Dashboard: `https://YOUR_HOST/ui` (monitor **snapshots**, not a live Snyk org). Mongo must be configured or the list stays empty (`snapshot_store: local_only`). On Fargate, open `/ui?api_key=…` once (the page stores the key in sessionStorage and strips it from the URL). `/docs` stays API-key gated.

**Good:** engine job log shows repo verify then agents; SARIF under **Security → Code scanning**; monitor may print `snapshot: persisted`.  
**Bad:** `engine unreachable` → GitHub still cannot see that URL. `auth failed` → secret ≠ engine `API_KEY`. Job skipped entirely → variable is not exactly `true`.

There is no second Python SDK. Humans use `athena`; agents use `athena mcp` on this machine (stdio, not on the ALB).

---

# Part 4 — Wrapper 2 of 3 — Jenkins

Same process as GitHub: prove the CLI command on a machine that can run it, first job = **local gate only**, engine secrets later. Cloud Jenkins agents **cannot** call `http://127.0.0.1:8012`.

This repo already contains [`Jenkinsfile`](../Jenkinsfile) (copy: [`plugins/Jenkinsfile`](../plugins/Jenkinsfile)). It does **not** call `credentials()` on the first run — missing credential IDs would fail the job before `athena` runs.

### Checkpoint J0 — agent can run Python

On the **Jenkins agent** (or your laptop if the agent is this PC):

```bash
python3 --version
python3 -m pip --version
cd /path/to/athena-sast-cli
python3 athena.py version
```

**Good:** Python 3.10+, pip exists, `Athena SAST v1.0.0`.  
**Bad:** no pip → install `python3-pip` on the agent. Do not create a job yet.

### Checkpoint J1 — same command the Jenkinsfile will exec

```bash
cd /path/to/athena-sast-cli
python3 athena.py scan --target . --modes pipeline \
  --format sarif --output /tmp/athena-jenkins-check.sarif \
  --json-output /tmp/athena-jenkins-check.json --fail-on high --quiet
echo "Exit: $?"
```

**Good:** exit `0` or `1`; SARIF file exists.  
**Bad:** exit `2` → stop.

### Checkpoint J2 — localhost trap (read)

If Jenkins is on another machine or a container, `127.0.0.1:8012` is **not** your FastAPI engine. First job must omit `REPO_URL` and omit API credentials.

### Checkpoint J3 — first job (local gate, no credentials)

1. Agent has this CLI folder as the job workspace (`pip install .` needs [`pyproject.toml`](../pyproject.toml) at the workspace root).
2. **New Item** → Pipeline → Pipeline script from SCM → this repo (it will load the root `Jenkinsfile`), **or** paste that file into the job.
3. Build. **Do not** add Credentials yet.

**Good:**

- Console shows `athena version` then the scan.
- Job result may be **UNSTABLE/FAILURE** with exit `1` (findings). That is the gate working.
- **Test Result** = JUnit. **Build artifacts** = `athena-results.sarif`, `.json`, `.xml` (`post { always }` still archives on failure).

**Bad:**

- `credentials not found` → you added `credentials('athena-api-key')` too early. Use the repo `Jenkinsfile` as shipped.
- `pip install` / `athena: not found` → Python/pip/PATH on the agent; workspace is not this CLI folder.

**Stop.** Do not add Azure until J3 is Good. Do not bind engine credentials until J3 is Good. The **Monitor** stage runs before the gate so a snapshot is recorded even when the scan later exits 1.

### Checkpoint J4 — engine from Jenkins (only if J3 passed **and** the **agent** can reach the engine URL)

**Admin** — Credentials → Secret text (IDs must match what you bind on the job):

| ID | Secret |
|----|--------|
| `athena-api-url` | engine URL the **agent** can reach, no trailing `/` |
| `athena-api-key` | same as FastAPI `API_KEY` |
| `athena-repo-token` | git token, or dummy if the repo is public |

**Job** — Environment / Bindings (not hardcoded in the Groovy file):

- `ATHENA_API_URL` ← `athena-api-url`
- `ATHENA_API_KEY` ← `athena-api-key`
- `ATHENA_REPO_TOKEN` ← `athena-repo-token`
- `REPO_URL` = `https://github.com/ORG/APP.git` (the repo to scan)

When both `ATHENA_API_URL` and `REPO_URL` are set, the Jenkinsfile switches to `code-review,secrets,iac,sca,pipeline`.

**Good:** log shows engine work (not only local regex). Exit still `0` or `1`.  
**Bad:** `engine unreachable` → agent cannot see that URL. `auth failed` → key ≠ engine `API_KEY`.

---

# Part 5 — Wrapper 3 of 3 — Azure DevOps

Microsoft-hosted `ubuntu-latest` **cannot** call `http://127.0.0.1:8012`. First pipeline = local gate. Do **not** set `continueOnError` on the scan step.

This repo already contains [`azure-pipelines.yml`](../azure-pipelines.yml) (copy: [`plugins/azure-pipelines.yml`](../plugins/azure-pipelines.yml)). `--repo` is added only when `ATHENA_API_URL` starts with `http`.

### Checkpoint A0 — you have an Azure project and this YAML in git

Azure needs the YAML **in the repo it builds**. If this folder is not in Azure Repos / GitHub connected to Azure, push it first.

### Checkpoint A1 — same laptop command as J1 / G1

Already proven if G1 or J1 passed. Re-run if this is a new machine.

### Checkpoint A2 — localhost trap (read)

A Microsoft-hosted agent is a VM in Azure’s cloud. It is not your laptop. Skip engine variables until the engine has a URL that VM can reach (or use a **self-hosted** agent on this PC).

### Checkpoint A3 — first pipeline (local gate, no secret values)

1. Pipelines → New pipeline → existing YAML → [`azure-pipelines.yml`](../azure-pipelines.yml) at repo root.
2. The YAML triggers on **every branch** (so the first push is not skipped if you are not on `main`). Run. **Do not** create Library secrets yet. Unset `ATHENA_API_URL` is treated as local gate (the file ignores a leftover `$(ATHENA_API_URL)` macro).
3. Workspace root must be this CLI (`pip install .`). If the Azure repo is the parent `athena_sast` folder, change the install step to `python3 -m pip install ./athena-sast-cli`.

**Good:**

- Install step prints `Athena SAST v1.0.0`.
- **Athena monitor** ran before the scan (does not fail on findings).
- Scan step exit `0` or `1` (1 = findings; pipeline **fails** — that is correct). Do not tick continue on error.
- Artifact `athena-sast-results` still publishes (`condition: always()`).

**Bad:**

- `ATHENA_API_URL is not set` with a full engine `--repo` → YAML is old; use the repo file as shipped.
- Exit `2` → read the scan log; do not add secrets to “fix” a missing `pyproject.toml`.

**Stop.** Do not add engine variables until A3 is Good.

### Checkpoint A4 — engine from Azure (only if A3 passed **and** the agent can reach the engine)

**Admin** — Pipelines → Library → variable group (or pipeline Variables):

| Name | Value | Padlock |
|------|--------|---------|
| `ATHENA_API_URL` | HTTPS or private agent-reachable engine URL, no trailing `/`. Do not use a public `http://` ALB. | no |
| `ATHENA_API_KEY` | same as FastAPI `API_KEY` | **yes** |
| `ATHENA_REPO_TOKEN` | git token | **yes** |

Link the variable group to the pipeline. When `ATHENA_API_URL` starts with `http`, the YAML adds `--repo` and full modes.

**Good:** scan log is not local-only; artifacts still publish.  
**Bad:** `engine unreachable` / `auth failed` — same meaning as GitHub G4.

For an **application** repo that is not this CLI: copy `athena-sast-cli` into that repo so `pip install .` works, **or** change the install path. Pin third-party actions/templates to a SHA when you add any.

---

# Part 6 — GitHub secrets on an application repo (same as Checkpoint G4)

If the repo you want scanned is **not** this CLI repo: Settings → Secrets → `ATHENA_API_URL`, `ATHENA_API_KEY`. Workflow `env:` must set those — composite actions cannot read `secrets.*` internally. Copy [`.github/workflows/athena-engine.yml`](../.github/workflows/athena-engine.yml) and set variable `ATHENA_ENABLE_ENGINE=true`. Pin `uses: YOUR_ORG/athena-sast-cli@COMMIT_SHA` (40-character SHA). Do not use `@main`.

Cursor MCP (this laptop only): copy [`.cursor/mcp.json.example`](../.cursor/mcp.json.example) to a local mcp config. `athena mcp` is stdio — never expose it on the ALB.

CLI container:

```bash
docker build -t athena-sast-cli .
docker run --rm -v "$PWD":/src -w /src athena-sast-cli scan --target . --modes pipeline
```

Do not pass secrets as `docker build --build-arg`. Use `-e ATHENA_API_KEY` at **run** time only.

---


# Part 7 — What each person is allowed to change

| Thing | Admin | Developer |
|-------|--------|-----------|
| FastAPI `API_KEY` / engine URL | yes | no |
| GitHub/Jenkins/Azure secret **values** | yes | no |
| `.github/workflows/athena.yml` / `Jenkinsfile` / `azure-pipelines.yml` in an app repo | can help | **yes — this is the usual user job** |
| `athena.yaml` in the app (`fail_on`, `exclude`) | can set a default | **yes** |
| CLI source code / rules | platform team | no (unless contributing) |

Copy [`athena.yaml`](../athena.yaml) to the **root of the app repo**. Example: keep `fail_on: high` so Medium findings do not fail the build until the team is ready.

---

# Part 8 — When something breaks

| You see | Meaning | What to do |
|---------|---------|------------|
| `ATHENA_API_URL is not set` | Env missing | `export` locally, or add GitHub/Jenkins/Azure secret |
| `auth failed` | Key rejected | CLI key must equal engine `API_KEY`. No extra spaces/quotes |
| `engine unreachable` | Network / engine down | `curl` health from the **same machine** that runs the CLI |
| Exit `1` with a findings table | Policy gate working | Fix the code, or temporarily raise `--fail-on` (admin decision) |
| Exit `2` | Tool did not finish | Do not treat as “no vulns”. Fix auth/path/engine |
| Empty SARIF on GitHub | Upload step skipped or file missing | Confirm `--output` path matches `sarif_file` |

---

# Honesty (do not over-claim to your boss)

- Local scan (`--local` or `pipeline` mode on disk) is **regex**. Engine scan is OpenGrep/Trivy/KICS/Syft.
- Findings have `"source": "local_owasp"` or `"source": "engine"` so you can tell them apart.
- `athena compliance` maps findings to control **names**. It does **not** make you “SOC 2 certified”.
