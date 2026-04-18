/**
 * Environment Builder — maps process.env to worker Env interfaces
 *
 * Each Cloudflare Worker expects a typed Env object injected by the runtime.
 * This module reads from process.env and constructs those objects, wiring in:
 *   - The Redis-backed KVNamespace adapter as BILLING_CACHE
 *   - The sentinel AI Gateway URL for the fetch interceptor
 *   - Sensible defaults for optional fields
 *
 * Performs startup validation: fails fast on missing required variables.
 */

import type { KVNamespace } from './kv-adapter.js';
import { AI_GATEWAY_SENTINEL } from './fetch-interceptor.js';

// ---------------------------------------------------------------------------
// Gateway Env
// ---------------------------------------------------------------------------

export interface GatewayEnv {
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  CF_AI_GATEWAY_URL: string;
  CF_AIG_TOKEN: string;
  GATEWAY_VERSION: string;
  ANTHROPIC_API_KEY: string;
  AIP_ENABLED: string;
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  OPENAI_API_KEY?: string;
  GEMINI_API_KEY?: string;
  BILLING_CACHE?: KVNamespace;
  BILLING_ENFORCEMENT_ENABLED?: string;
  MNEMOM_ANALYZE_URL?: string;
  MNEMOM_API_KEY?: string;
  MNEMOM_LICENSE_JWT?: string;
}

// ---------------------------------------------------------------------------
// Observer Env
// ---------------------------------------------------------------------------

export interface ObserverEnv {
  CF_ACCOUNT_ID: string;
  CF_API_TOKEN: string;
  CF_AI_GATEWAY_URL?: string;
  GATEWAY_ID: string;
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  ANTHROPIC_API_KEY: string;
  ANALYSIS_API_KEY?: string;
  OTLP_ENDPOINT?: string;
  OTLP_AUTH?: string;
  STRIPE_SECRET_KEY?: string;
}

// ---------------------------------------------------------------------------
// API Env
// ---------------------------------------------------------------------------

export interface ApiEnv {
  SUPABASE_URL: string;
  SUPABASE_SECRET_KEY: string;
  SUPABASE_JWT_SECRET: string;
  MNEMOM_PUBLISH_KEY: string;
  STRIPE_SECRET_KEY: string;
  STRIPE_WEBHOOK_SECRET: string;
  RESEND_API_KEY: string;
  ANTHROPIC_API_KEY: string;
  LICENSE_SIGNING_SECRET: string;
  HUBSPOT_API_KEY?: string;
  SLACK_WEBHOOK_URL?: string;
  BILLING_CACHE?: KVNamespace;
}

// ---------------------------------------------------------------------------
// Validation helper
// ---------------------------------------------------------------------------

class EnvValidationError extends Error {
  constructor(missing: string[]) {
    super(
      `Missing required environment variables:\n  ${missing.join('\n  ')}\n\n` +
        'Set them in your .env or deployment configuration.',
    );
    this.name = 'EnvValidationError';
  }
}

function requireEnv(keys: string[]): void {
  const missing = keys.filter((k) => !process.env[k]);
  if (missing.length > 0) {
    throw new EnvValidationError(missing);
  }
}

function env(key: string, fallback?: string): string {
  return process.env[key] ?? fallback ?? '';
}

// ---------------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------------

export function buildGatewayEnv(kv?: KVNamespace): GatewayEnv {
  requireEnv(['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'ANTHROPIC_API_KEY']);

  return {
    SUPABASE_URL: env('SUPABASE_URL'),
    SUPABASE_SECRET_KEY: env('SUPABASE_SECRET_KEY'),
    CF_AI_GATEWAY_URL: AI_GATEWAY_SENTINEL,
    CF_AIG_TOKEN: env('CF_AIG_TOKEN', 'self-hosted'),
    GATEWAY_VERSION: env('GATEWAY_VERSION', '1.0.0-selfhosted'),
    ANTHROPIC_API_KEY: env('ANTHROPIC_API_KEY'),
    AIP_ENABLED: env('AIP_ENABLED', 'true'),
    OTLP_ENDPOINT: process.env.OTLP_ENDPOINT,
    OTLP_AUTH: process.env.OTLP_AUTH,
    OPENAI_API_KEY: process.env.OPENAI_API_KEY,
    GEMINI_API_KEY: process.env.GEMINI_API_KEY,
    BILLING_CACHE: kv,
    BILLING_ENFORCEMENT_ENABLED: env('BILLING_ENFORCEMENT_ENABLED', 'false'),
    MNEMOM_ANALYZE_URL: process.env.MNEMOM_ANALYZE_URL,
    MNEMOM_API_KEY: process.env.MNEMOM_API_KEY,
    MNEMOM_LICENSE_JWT: process.env.MNEMOM_LICENSE_JWT,
  };
}

export function buildObserverEnv(): ObserverEnv {
  requireEnv(['SUPABASE_URL', 'SUPABASE_SECRET_KEY', 'ANTHROPIC_API_KEY']);

  return {
    // Self-hosted: no CF account — set to empty; CF API calls fail gracefully
    CF_ACCOUNT_ID: env('CF_ACCOUNT_ID', ''),
    CF_API_TOKEN: env('CF_API_TOKEN', ''),
    CF_AI_GATEWAY_URL: process.env.CF_AI_GATEWAY_URL,
    GATEWAY_ID: env('GATEWAY_ID', 'self-hosted'),
    SUPABASE_URL: env('SUPABASE_URL'),
    SUPABASE_SECRET_KEY: env('SUPABASE_SECRET_KEY'),
    ANTHROPIC_API_KEY: env('ANTHROPIC_API_KEY'),
    ANALYSIS_API_KEY: process.env.ANALYSIS_API_KEY,
    OTLP_ENDPOINT: process.env.OTLP_ENDPOINT,
    OTLP_AUTH: process.env.OTLP_AUTH,
    STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY,
  };
}

export function buildApiEnv(kv?: KVNamespace): ApiEnv {
  requireEnv([
    'SUPABASE_URL',
    'SUPABASE_SECRET_KEY',
    'SUPABASE_JWT_SECRET',
    'ANTHROPIC_API_KEY',
  ]);

  return {
    SUPABASE_URL: env('SUPABASE_URL'),
    SUPABASE_SECRET_KEY: env('SUPABASE_SECRET_KEY'),
    SUPABASE_JWT_SECRET: env('SUPABASE_JWT_SECRET'),
    MNEMOM_PUBLISH_KEY: env('MNEMOM_PUBLISH_KEY', ''),
    STRIPE_SECRET_KEY: env('STRIPE_SECRET_KEY', ''),
    STRIPE_WEBHOOK_SECRET: env('STRIPE_WEBHOOK_SECRET', ''),
    RESEND_API_KEY: env('RESEND_API_KEY', ''),
    ANTHROPIC_API_KEY: env('ANTHROPIC_API_KEY'),
    LICENSE_SIGNING_SECRET: env('LICENSE_SIGNING_SECRET', ''),
    HUBSPOT_API_KEY: process.env.HUBSPOT_API_KEY,
    SLACK_WEBHOOK_URL: process.env.SLACK_WEBHOOK_URL,
    BILLING_CACHE: kv,
  };
}
