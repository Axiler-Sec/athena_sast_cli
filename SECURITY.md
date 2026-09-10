# Security policy

## Report a vulnerability

Do **not** open a public issue for leaked tokens, `.env` files, or a working exploit.

Email the maintainers via GitHub Security Advisories on
[Axiler-Sec/athena_sast_cli](https://github.com/Axiler-Sec/athena_sast_cli/security/advisories/new)
(or the org security contact). Include the affected version/tag and a
reproducer that does **not** paste live `ATHENA_API_KEY` values.

## What this CLI never ships

- Engine `API_KEY` / `ATHENA_API_KEY` / git tokens
- `.env` files (gitignored; Docker image does not `COPY .env`)
- A default engine URL in code (forks must not phone home)
- MCP on a public port (`athena mcp` is stdio on the operator’s machine)

## Operator secrets

| Name | Role |
|------|------|
| `ATHENA_API_KEY` | Scanner-role key for `X-API-Key`. Prefer `ath_live_…` (not org-admin). |
| `ATHENA_REPO_TOKEN` | Git clone of **private** repos only. |
| `ATHENA_API_URL` | Engine base URL, **HTTPS** in cloud CI. Set privately. Do not publish the hostname in docs, issues, or examples. |

Never pass keys as CLI flags. Never `set -x` in workflows. The CLI redacts
`ath_live_` / `ath_test_` / `ath_canary_` and common vendor prefixes in logs.

## GitHub Action

Pin `uses: Axiler-Sec/athena_sast_cli@<40-character-sha>`. Do not use `@main`.
Use `pull_request`, never `pull_request_target` with a checkout of the PR head.
