# mnemom-platform

[![CI](https://github.com/mnemom/mnemom-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/mnemom/mnemom-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mnemom/mnemom-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/mnemom/mnemom-platform/actions/workflows/codeql.yml)
[![npm](https://img.shields.io/npm/v/%40mnemom%2Fsmoltbot.svg)](https://www.npmjs.com/package/@mnemom/smoltbot)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![AAP](https://img.shields.io/badge/AAP-compliant-green.svg)](https://github.com/mnemom/aap)
[![AIP](https://img.shields.io/badge/AIP-compliant-green.svg)](https://github.com/mnemom/aip)

Transparent AI agent tracing. [AAP](https://github.com/mnemom/aap)-compliant.

mnemom observes your AI agent's API calls and builds verifiable alignment traces — what decisions were made, what alternatives were considered, and whether behavior matches declared values. Your prompts and responses are never stored.

## Documentation

Full documentation is at **[docs.mnemom.ai/smoltbot/overview](https://docs.mnemom.ai/smoltbot/overview)**.

## Quick Start

```bash
npm install -g smoltbot
smoltbot init
```

That's it. `smoltbot init` configures your local environment to route API calls through the Mnemom gateway, where they're traced and verified. Your API key never leaves your machine — only a SHA-256 hash is used for agent identification.

## CLI Commands

| Command | Description |
|---------|-------------|
| `smoltbot init` | Configure tracing for your AI agent |
| `smoltbot status` | Show agent status and connection info |
| `smoltbot integrity` | Display integrity score and verification stats |
| `smoltbot logs [-l N]` | Show recent traces and actions |

## Supported Providers

| Provider | Models | Thinking/AIP | Auth |
|----------|--------|-------------|------|
| Anthropic | Claude Opus 4.6, Opus 4.5, Sonnet 4.5 | Full (thinking blocks) | `x-api-key` |
| OpenAI | GPT-5.2, GPT-5.2 Pro, GPT-5 | Via reasoning summaries | `Authorization: Bearer` |
| Gemini | Gemini 2.5 Pro, Gemini 3 Pro | Full (thought parts) | `x-goog-api-key` |

## How It Works

```
                    ┌─── /anthropic/* ──→ Anthropic (Claude)
Your App → smoltbot ├─── /openai/*    ──→ OpenAI (GPT-5)
           gateway  └─── /gemini/*    ──→ Google (Gemini)
                ↓
           CF AI Gateway
                ↓
           Observer Worker
                ↓
         AP-Trace + Verify → Supabase
                ↓
         Dashboard (mnemom.ai)
```

1. **Gateway** — A Cloudflare Worker that intercepts API requests to Anthropic, OpenAI, and Gemini. It identifies your agent via API key hash (zero-config), attaches tracing metadata, injects thinking/reasoning per provider (Wave 1), performs real-time integrity checking (Wave 2), injects conscience nudges (Wave 3), and delivers webhooks (Wave 4). Your prompts and responses pass through unchanged.

2. **Observer** — A scheduled Cloudflare Worker that processes AI Gateway logs. It extracts thinking blocks (Anthropic/Gemini) or reasoning summaries (OpenAI) from responses, analyzes decisions with Claude Haiku, builds [AP-Traces](https://github.com/mnemom/aap), verifies them against your agent's alignment card using the AAP SDK, and runs [AIP](https://github.com/mnemom/aip) integrity checks. Creates enforcement nudges when violations are detected.

3. **API** — Serves agent data, traces, integrity scores, drift alerts, enforcement status, and a unified conscience timeline. Powers both the CLI and the web dashboard.

4. **CLI** — The `smoltbot` command. Configures your local environment and queries your agent's transparency data.

5. **Dashboard** — Web UI at [mnemom.ai](https://mnemom.ai) where you can view the conscience timeline, claim your agent, and monitor alignment.

## Architecture

```
smoltbot/
├── cli/          # CLI tool (npm package)
├── gateway/      # Cloudflare Worker — API proxy + tracing
├── observer/     # Cloudflare Worker — trace builder + AAP verification
├── prover/       # ZK proving service (Fly.io)
└── zkvm/         # Zero-knowledge VM (core, host, wasm-verifier)
```

> **Note:** `api/` and `database/` have been extracted to the private [`mnemom/mnemom-api`](https://github.com/mnemom/mnemom-api) repository.

## Claiming Your Agent

After `smoltbot init`, your agent is registered automatically. To link it to your Mnemom account:

1. Run `smoltbot status` to get your agent ID
2. Go to [mnemom.ai/claim](https://mnemom.ai/claim)
3. Paste your agent ID and prove ownership with your API key hash

Claiming gives you a private dashboard with full trace history, integrity scores, and drift detection.

## What Gets Traced

mnemom builds [AP-Traces](https://github.com/mnemom/aap) that record:

- **Action** — What the agent did (type, name, category)
- **Decision** — What alternatives were considered and why one was selected
- **Escalation** — Whether the agent escalated to a human and why
- **Verification** — Whether the trace is consistent with the agent's declared alignment card
- **Integrity** — Real-time [AIP](https://github.com/mnemom/aip) analysis of thinking blocks, with verdict (clear/review_needed/boundary_violation)

What is **not** stored: your prompts, responses, or API key.

### AIP Compatibility Matrix

| Provider/Model | AIP Support | Method |
|----------------|-------------|--------|
| Anthropic reasoning models (Opus, Sonnet) | Full | Thinking blocks analyzed directly |
| OpenAI GPT-5 Thinking series | Partial | Reasoning summaries (reduced confidence) |
| Gemini 2.5/3 with thinking | Full | Thought parts analyzed directly |
| Non-reasoning models | Tracing only | Synthetic clear verdict |
| Legacy OpenAI (o3/o4-mini) | Unsupported | Reasoning encrypted |

## Enforcement Modes

mnemom supports three enforcement modes for integrity violations:

| Mode | Behavior |
|------|----------|
| `observe` | Detect violations, record them, take no action (default) |
| `nudge` | Detect violations, inject feedback into the agent's next request via system prompt — the agent sees it and can self-correct |
| `enforce` | Hard block with 403 for non-streaming; falls back to nudge for streaming |

When a violation is detected in `nudge` or `enforce` mode, a pending nudge record is created. On the agent's next request, the gateway injects an integrity notice into the system prompt. The agent sees the notice, can review its approach, and self-correct. The nudge delivery is tracked in the conscience timeline. Enforcement works across all providers where AIP is supported.

Set enforcement mode via the API: `PUT /v1/agents/:id/enforcement` with `{"mode": "nudge"}`.

## Current Limitations

- **API key auth only** — Agent identification uses API key hashing (SHA-256, works identically across all providers). OAuth and other auth methods are not supported.
- **AIP requires reasoning models** — AIP integrity checking requires models with exposed thinking (Anthropic, Gemini, GPT-5 Thinking). Models without thinking get synthetic clear verdicts.
- **Hosted gateway** — The default gateway runs on Mnemom infrastructure. Self-hosting is possible but requires manual setup.

## Dependencies

- [Agent Alignment Protocol (AAP)](https://github.com/mnemom/aap) — `@mnemom/agent-alignment-protocol@0.1.8` on npm
- [Agent Integrity Protocol (AIP)](https://github.com/mnemom/aip) — `@mnemom/agent-integrity-protocol@0.1.4` on npm
- [Cloudflare Workers](https://workers.cloudflare.com/) — Gateway, observer, and API hosting
- [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/) — Request logging and analytics
- [Supabase](https://supabase.com/) — Postgres database with row-level security
- API keys: Anthropic (required for AIP analysis), OpenAI and Gemini (optional, for multi-provider tracing)

## Self-Hosting

mnemom-platform is designed to run on Cloudflare Workers + Supabase. To self-host:

1. Create a Supabase project and run the schema from [`mnemom-api`](https://github.com/mnemom/mnemom-api)
2. Deploy workers: `cd gateway && wrangler deploy`, `cd observer && wrangler deploy`, and deploy the API from `mnemom-api`
3. Set secrets on each worker via `wrangler secret put`
4. Configure a Cloudflare AI Gateway and point the gateway worker to it
5. Update the CLI's gateway URL: `smoltbot init --gateway=https://your-domain.com`

## Contributing

Contributions welcome. Please open an issue first to discuss what you'd like to change.

## License

[Apache-2.0](LICENSE)

Copyright 2026 Mnemom LLC
