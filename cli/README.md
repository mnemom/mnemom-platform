# Mnemom CLI

[![CI](https://github.com/mnemom/mnemom-platform/actions/workflows/ci.yml/badge.svg)](https://github.com/mnemom/mnemom-platform/actions/workflows/ci.yml)
[![CodeQL](https://github.com/mnemom/mnemom-platform/actions/workflows/codeql.yml/badge.svg)](https://github.com/mnemom/mnemom-platform/actions/workflows/codeql.yml)
[![npm](https://img.shields.io/npm/v/%40mnemom%2Fmnemom.svg)](https://www.npmjs.com/package/@mnemom/mnemom)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![AAP](https://img.shields.io/badge/AAP-compliant-green.svg)](https://github.com/mnemom/aap)
[![AIP](https://img.shields.io/badge/AIP-compliant-green.svg)](https://github.com/mnemom/aip)

Transparent AI agent tracing. [AAP](https://github.com/mnemom/aap)-compliant.

Mnemom observes your AI agent's API calls and builds verifiable alignment traces — what decisions were made, what alternatives were considered, and whether behavior matches declared values. Your prompts and responses are never stored.

## Documentation

Full documentation is at **[docs.mnemom.ai](https://docs.mnemom.ai)**.

## Quick Start

```bash
npm install -g @mnemom/mnemom
mnemom init
```

That's it. `mnemom init` detects your configured AI provider API keys (Anthropic, OpenAI, Gemini) and configures your local environment to route API calls through the Mnemom gateway, where they're traced and verified. Your API keys never leave your machine — only SHA-256 hashes are used for agent identification.

## Supported Providers

| Provider | Models | Thinking/AIP | Auth |
|----------|--------|-------------|------|
| Anthropic | Claude Opus 4.6, Opus 4.5, Sonnet 4.5 | Full (thinking blocks) | `x-api-key` |
| OpenAI | GPT-5.2, GPT-5.2 Pro, GPT-5 | Via reasoning summaries | `Authorization: Bearer` |
| Gemini | Gemini 2.5 Pro, Gemini 3 Pro | Full (thought parts) | `x-goog-api-key` |

## CLI Commands

| Command | Description |
|---------|-------------|
| `mnemom init` | Configure tracing for your AI agent (multi-provider) |
| `mnemom status` | Show agent status, providers, and connection info |
| `mnemom integrity` | Display integrity score and verification stats |
| `mnemom logs [-l N]` | Show recent traces and actions |
| `mnemom card show` | Display active alignment card |
| `mnemom card publish <file>` | Publish alignment card from JSON file |
| `mnemom card validate <file>` | Validate card JSON locally |

## How It Works

```
                   ┌─── /anthropic/* ──→ Anthropic (Claude)
Your App → mnemom  ├─── /openai/*    ──→ OpenAI (GPT-5)
           gateway └─── /gemini/*    ──→ Google (Gemini)
               ↓
          CF AI Gateway
               ↓
          Observer Worker
               ↓
        AP-Trace + Verify → Supabase
               ↓
        Dashboard (mnemom.ai)
```

1. **Gateway** — A Cloudflare Worker that intercepts API requests to Anthropic, OpenAI, and Gemini. It identifies your agent via API key hash (zero-config), attaches tracing metadata, injects thinking/reasoning per provider, performs real-time integrity checking, injects conscience nudges, and delivers webhooks. Your prompts and responses pass through unchanged.

2. **Observer** — A scheduled Cloudflare Worker that processes AI Gateway logs. It extracts thinking blocks (Anthropic/Gemini) or reasoning summaries (OpenAI) from responses, analyzes decisions with Claude Haiku, builds [AP-Traces](https://github.com/mnemom/aap), verifies them against your agent's alignment card using the AAP SDK, and runs [AIP](https://github.com/mnemom/aip) integrity checks. Creates enforcement nudges when violations are detected.

3. **API** — Serves agent data, traces, integrity scores, drift alerts, enforcement status, and a unified conscience timeline. Powers both the CLI and the web dashboard.

4. **CLI** — The `mnemom` command. Configures your local environment and queries your agent's transparency data.

5. **Dashboard** — Web UI at [mnemom.ai](https://mnemom.ai) where you can view the conscience timeline, claim your agent, and monitor alignment.

## What Gets Traced

Mnemom builds [AP-Traces](https://github.com/mnemom/aap) that record:

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

## Enforcement Modes

| Mode | Behavior |
|------|----------|
| `observe` | Detect violations, record them, take no action (default) |
| `nudge` | Detect violations, inject feedback into the agent's next request via system prompt — the agent sees it and can self-correct |
| `enforce` | Hard block with 403 for non-streaming; falls back to nudge for streaming |

Enforcement works across all providers where AIP is supported.

## Current Limitations

- **API key auth only** — Agent identification uses API key hashing (SHA-256, works identically across all providers). OAuth and other auth methods are not supported.
- **AIP requires reasoning models** — AIP integrity checking requires models with exposed thinking. Models without thinking get synthetic clear verdicts.
- **Hosted gateway** — The default gateway runs on Mnemom infrastructure. Self-hosting is possible but requires manual setup.

## Dependencies

- [Agent Alignment Protocol (AAP)](https://github.com/mnemom/aap) — `@mnemom/agent-alignment-protocol@1.0.0` on npm
- [Agent Integrity Protocol (AIP)](https://github.com/mnemom/aip) — `@mnemom/agent-integrity-protocol@1.0.0` on npm
- [Cloudflare Workers](https://workers.cloudflare.com/) — Gateway, observer, and API hosting
- [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/) — Request logging and analytics
- [Supabase](https://supabase.com/) — Postgres database with row-level security
- API keys: Anthropic (required for AIP analysis), OpenAI and Gemini (optional, for multi-provider tracing)

## Supply Chain

All `@mnemom/*` packages are published with [SLSA build provenance](https://docs.mnemom.ai/guides/supply-chain-trust). Verify with `npm audit signatures`.

## License

[Apache-2.0](LICENSE)

Copyright 2026 Mnemom LLC
