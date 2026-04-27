# AGENTS.md — mnemom-platform

You are a coding agent working on **mnemom-platform** (formerly
`smoltbot`) — the Safe House gateway, observer, CLI, and proxy that
sit on the Mnemom critical path.

Audience: AI coding tools (Claude Code, Cursor, Cline, Aider) and
humans onboarding via them.

## What this repo is

The platform multi-package — four deployables sharing internal
libraries:

| Sub-package | What it is | Deploys to |
|---|---|---|
| `gateway/` | Pre-action enforcement Worker (the gateway in front of agent traffic) | Cloudflare Worker |
| `observer/` | Post-hoc verifier + trust-rating updater | Cloudflare Worker |
| `proxy/` | Lightweight upstream proxy | Cloudflare Worker |
| `cli/` | `mnemom` and `smoltbot`-shim CLIs | npm (`@mnemom/mnemom`) |
| `shared/` | Internal libs: `policy-engine`, `safe-house` (file: deps) |

The CLI exposes both `mnemom` and the legacy `smoltbot` binary name.
Production gateway runs on api.mnemom.ai and serves all live agent
traffic — small changes ship behind the orchestrator's staging gate.

License: Apache-2.0.

## Stack

- All Workers: TypeScript + Wrangler (`wrangler dev`,
  `wrangler deploy`).
- CLI: tsc + tsx.
- Tests: vitest.
- Top-level lint: eslint + prettier; husky for git hooks.
- Internal libs are linked via `file:../shared/...` deps — running
  `npm install` in a subpackage builds them transitively.

## Install + dev

```bash
# Top-level (lint everything)
npm install
npm run lint

# Per sub-package
cd gateway   && npm install && npm test
cd observer  && npm install && npm test
cd proxy     && npm install && npm test
cd cli       && npm install && npm run build && npm test

# Local Worker dev (hot reload)
cd gateway && npm run dev          # spins up wrangler dev for the gateway
cd observer && npm run dev
```

## Project layout

```
gateway/                  # Pre-action gateway Worker
  src/
  wrangler.jsonc
  package.json
observer/                 # Post-hoc observer Worker
  src/
  wrangler.jsonc
proxy/                    # Lightweight proxy Worker
  src/
cli/                      # @mnemom/mnemom + smoltbot-shim
  src/
  package.json
shared/                   # Internal libs consumed via file: deps
  policy-engine/
  safe-house/
deploy/                   # Local helpers (deploys themselves go through mnemom/deploy)
docs/
scripts/
```

## Conventions

- **The gateway is the critical path.** Production agent traffic
  flows through it. Every PR that touches `gateway/src/` is reviewed
  for performance and correctness, not just lint.
- **`shared/` libs are internal only.** Don't publish them to npm.
  They're linked via `file:` deps because they're tightly coupled to
  consumer versions; publishing creates a release-coordination cliff.
- **Wire-format compatibility with mnemom-types.** Anything that
  travels between Worker and observer (or Worker and SDK) must be
  representable in `@mnemom/types`. If a new field is needed, add it
  to mnemom-types first.
- **Apache-2.0** for the published CLI; the Workers + shared libs
  inherit the LICENSE at the repo root.
- The CLI ships **both** `mnemom` and `smoltbot` binaries during the
  rename window. Don't drop the `smoltbot` shim until the deprecation
  window closes.
- Commit messages: imperative, concise, describe the **why**.

## Branch protection + deploy

- Never commit directly to `main`. Always feature branch first.
- Branch protection enforced.
- **Allowed:**
  - Trigger staging deploy:
    `gh workflow run deploy.yml --repo mnemom/deploy -f repos=mnemom-platform -f environment=staging`
  - Check deploy status:
    `gh run list --repo mnemom/deploy --workflow deploy.yml --limit 5`
  - Roll back staging gateway:
    `gh workflow run rollback.yml --repo mnemom/deploy -f service=gateway -f environment=staging`
  - Roll back staging observer:
    `gh workflow run rollback.yml --repo mnemom/deploy -f service=observer -f environment=staging`
- **Not allowed:**
  - Approve or trigger production deploys (GH environment protection).
  - Roll back production without explicit human instruction.
  - Modify deploy workflows in the deploy repo.

## What you should NOT do

- Don't deploy to production from a local machine. Production is
  orchestrated only.
- Don't bypass the policy-engine in the gateway. Every action goes
  through it; carving out exceptions defeats the point of the
  Alignment Card.
- Don't add bot-only code paths (no UA cloaking) — that violates
  the public Mnemom Agent-Readability Commitment (#5 on /for-agents).
- Don't introduce a Worker dependency that breaks compatibility with
  Cloudflare's Worker runtime (no `node:fs`, no `process.env` outside
  bindings, etc.).
- Don't drop the `smoltbot` CLI shim until the rename window closes.
- Don't skip pre-commit hooks (`--no-verify`).
- Don't `git push --force` to `main`.

## Cross-links

- **Protocols this platform implements**:
  [AAP](https://github.com/mnemom/aap) (Alignment Card schema +
  verification) and [AIP](https://github.com/mnemom/aip) (real-time
  thinking-block analysis).
- **Telemetry**: [aip-otel-exporter](https://github.com/mnemom/aip-otel-exporter)
  ships verdicts to OTel.
- **Type definitions**: [mnemom-types](https://github.com/mnemom/mnemom-types).
- **Public commitments touching this repo**:
  https://www.mnemom.ai/for-agents — particularly #5 (no UA
  cloaking) and #6 (open protocols).
- **Mintlify-hosted operator docs**: https://docs.mnemom.ai/gateway
  and https://docs.mnemom.ai/concepts.
