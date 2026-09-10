# Security policy

Do **not** open a public issue for leaked tokens, `.env` files, or a working exploit.

Report via GitHub Security Advisories on
[Axiler-Sec/athena_sast_cli](https://github.com/Axiler-Sec/athena_sast_cli/security/advisories/new).
Include the affected version/tag. Do not paste live `ATHENA_API_KEY` values.

This CLI does not ship engine keys, `.env` files, or a default engine URL.

Set `ATHENA_API_URL` and `ATHENA_API_KEY` in a secret store. Never pass keys as CLI flags. Never `set -x` in workflows.

Pin `uses: Axiler-Sec/athena_sast_cli@<40-character-sha>` (or a release tag). Do not use `@main`. Use `pull_request`, never `pull_request_target` with a checkout of the PR head.
