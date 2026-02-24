import { exec } from "node:child_process";
import * as crypto from "node:crypto";
import {
  loadConfig,
  saveConfig,
  deriveAgentId,
  deriveAgentIdWithName,
  type AgentConfig,
} from "../lib/config.js";
import {
  detectProviders,
  configureSmoltbotProviders,
  configureNamedAgentProviders,
  PROVIDER_CONFIG_KEYS,
  type Provider,
  type ModelDefinition,
} from "../lib/openclaw.js";
import {
  getLatestModels,
  detectProvider,
  formatModelName,
} from "../lib/models.js";
import { askYesNo, askInput, askSelect, isInteractive } from "../lib/prompt.js";
import { fmt } from "../lib/format.js";

const GATEWAY_URL = "https://gateway.mnemom.ai";
const DASHBOARD_URL = "https://mnemom.ai";

/** Validate agent name: alphanumeric + hyphens, 1-32 chars, not "default" */
function validateAgentName(name: string): string | null {
  if (name.toLowerCase() === "default") {
    return '"default" is reserved. Choose a different name.';
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9-]{0,30}[a-zA-Z0-9]$/.test(name) && !/^[a-zA-Z0-9]{1,2}$/.test(name)) {
    return "Name must be 1-32 alphanumeric characters or hyphens, cannot start/end with hyphen.";
  }
  return null;
}

export interface RegisterOptions {
  openclaw?: boolean;
  standalone?: boolean;
  setDefault?: boolean;
}

export async function registerCommand(
  name: string,
  options: RegisterOptions = {}
): Promise<void> {
  console.log(fmt.header("smoltbot register - Add a named agent"));
  console.log();

  // Validate name
  const nameError = validateAgentName(name);
  if (nameError) {
    console.log(fmt.error(nameError) + "\n");
    process.exit(1);
  }

  // Load config
  const config = loadConfig();
  if (!config) {
    console.log(fmt.error("smoltbot is not initialized") + "\n");
    console.log("Run `smoltbot init` first to set up the default agent.\n");
    process.exit(1);
  }

  // Check for duplicate
  if (config.agents[name]) {
    console.log(fmt.warn(`Agent "${name}" already exists`) + "\n");
    console.log(fmt.label("  Agent ID:", ` ${config.agents[name].agentId}`));
    console.log();

    if (!isInteractive()) {
      process.exit(1);
    }

    const overwrite = await askYesNo(`Overwrite agent "${name}"?`, false);
    if (!overwrite) {
      console.log("\nNo changes made.\n");
      return;
    }
    console.log();
  }

  // Detect providers
  const detection = detectProviders();

  if (!detection.installed && !options.standalone) {
    console.log(fmt.error("OpenClaw not found. Use --standalone for standalone mode.") + "\n");
    process.exit(1);
  }

  // Find API key for agent ID derivation
  let apiKey: string | undefined;
  let selectedProvider: Provider = "anthropic";

  const PROVIDER_LABELS: Record<Provider, string> = {
    anthropic: "Anthropic",
    openai: "OpenAI",
    gemini: "Gemini",
  };

  const KEY_PREFIXES: Record<Provider, string> = {
    anthropic: "sk-ant-",
    openai: "sk-",
    gemini: "AIza",
  };

  const ENV_VARS: Record<Provider, string> = {
    anthropic: "ANTHROPIC_API_KEY",
    openai: "OPENAI_API_KEY",
    gemini: "GEMINI_API_KEY",
  };

  if (options.standalone || !detection.installed) {
    // Standalone: ask which provider, then prompt for key
    if (isInteractive()) {
      const choice = await askSelect(
        "Which provider will this agent use?",
        ["Anthropic", "OpenAI", "Gemini"],
      );
      const providerMap: Record<string, Provider> = {
        Anthropic: "anthropic",
        OpenAI: "openai",
        Gemini: "gemini",
      };
      selectedProvider = (choice ? providerMap[choice] : "anthropic") || "anthropic";

      apiKey = await askInput(
        `${PROVIDER_LABELS[selectedProvider]} API key (${KEY_PREFIXES[selectedProvider]}...):`,
        true,
      );
    } else {
      apiKey = process.env.ANTHROPIC_API_KEY
        || process.env.OPENAI_API_KEY
        || process.env.GEMINI_API_KEY;
    }
  } else {
    // OpenClaw: use first available key
    for (const provider of ["anthropic", "openai", "gemini"] as Provider[]) {
      const info = detection.providers[provider];
      if (info.hasApiKey && info.apiKey) {
        apiKey = info.apiKey;
        break;
      }
    }
  }

  if (!apiKey) {
    console.log(fmt.error("No API key available for agent identity") + "\n");
    process.exit(1);
  }

  // Derive agent ID with name
  const agentId = deriveAgentIdWithName(apiKey, name);
  console.log(fmt.label("Agent ID:", ` ${agentId}`));
  console.log(fmt.label("Name:    ", ` ${name}`));
  console.log(fmt.label("Gateway: ", ` ${config.gateway} (x-smoltbot-agent: ${name})`));
  console.log();

  // Configure OpenClaw providers for named agent
  if (detection.installed && !options.standalone) {
    console.log("Configuring OpenClaw providers for named agent...\n");

    const verifiedProviders: { provider: Provider; apiKey: string }[] = [];
    for (const provider of ["anthropic", "openai", "gemini"] as Provider[]) {
      const info = detection.providers[provider];
      if (info.hasApiKey && info.apiKey) {
        verifiedProviders.push({ provider, apiKey: info.apiKey });
      }
    }

    if (verifiedProviders.length > 0) {
      const latestModels = getLatestModels();
      const providerData: Partial<Record<Provider, { apiKey: string; models: ModelDefinition[] }>> = {};

      for (const { provider, apiKey: key } of verifiedProviders) {
        providerData[provider] = {
          apiKey: key,
          models: latestModels[provider],
        };
      }

      const configured = configureNamedAgentProviders(name, providerData);
      for (const provider of configured) {
        const configKey = `smoltbot-${name}` + (provider === "anthropic" ? "" : `-${provider}`);
        console.log(fmt.success(`${provider} provider configured (${configKey})`));
      }
      console.log();
    }
  }

  // Save agent to config
  const agentConfig: AgentConfig = {
    agentId,
    openclawConfigured: detection.installed && !options.standalone,
    providers: options.standalone ? [selectedProvider] : undefined,
    configuredAt: new Date().toISOString(),
  };

  config.agents[name] = agentConfig;

  if (options.setDefault) {
    config.defaultAgent = name;
    console.log(fmt.success(`Set "${name}" as default agent`) + "\n");
  }

  saveConfig(config);
  console.log(fmt.success(`Agent "${name}" registered locally`) + "\n");

  // Make a real API call through the gateway to verify key AND create agent on server
  // This MUST succeed — the agent doesn't exist on the server until this call goes through
  const gatewayProvider = options.standalone ? selectedProvider : "anthropic";
  let verified = false;

  while (!verified) {
    console.log(`Connecting to gateway...`);

    const testResult = await testGatewayCall(
      config.gateway,
      name,
      gatewayProvider,
      apiKey,
      config.mnemomApiKey,
    );

    if (testResult.ok && testResult.response) {
      console.log(fmt.success("Connected! First response from " + name + ":") + "\n");
      console.log(`    "${testResult.response}"\n`);
      console.log(fmt.success("Agent created on mnemom.ai") + "\n");
      verified = true;
    } else if (testResult.authError) {
      console.log(fmt.error(`API key invalid: ${testResult.error}`) + "\n");
      console.log("  Check your API key and try again with:");
      console.log(`    smoltbot register ${name}\n`);
      return;
    } else {
      console.log(fmt.error(`Connection failed: ${testResult.error}`) + "\n");

      if (!isInteractive()) {
        console.log("  Run `smoltbot register " + name + "` to retry.\n");
        return;
      }

      const retry = await askYesNo("Retry?", true);
      if (!retry) {
        console.log("\n  Agent is saved locally but NOT created on the server.");
        console.log(`  Run \`smoltbot register ${name}\` to try again.\n`);
        return;
      }
      console.log();
    }
  }

  // Only show claim + next steps after successful gateway verification
  // Include hash proof in URL so the website can auto-fill it
  // Hash proof must match how the gateway computed agent_hash:
  // named agents use hash(apiKey + '|' + name), default uses hash(apiKey)
  const hashInput = apiKey + "|" + name;
  const hashProof = crypto.createHash("sha256").update(hashInput).digest("hex");
  const claimUrl = `${DASHBOARD_URL}/claim/${agentId}?hash=${hashProof}`;
  console.log(fmt.section("Link to your Mnemom account"));
  console.log();
  console.log(`  Sign in (or create a free account) to see your agent's`);
  console.log(`  traces and manage its alignment card.\n`);
  console.log(`  ${claimUrl}\n`);

  if (isInteractive()) {
    const openBrowser = await askYesNo("Open in browser?", true);
    if (openBrowser) {
      openUrl(claimUrl);
      console.log();
    } else {
      console.log();
    }
  }

  // Show usage instructions
  console.log(fmt.section("Start using your agent"));
  console.log();

  if (detection.installed && !options.standalone) {
    console.log(`  openclaw models set smoltbot-${name}/<model-id>`);
  } else {
    console.log(`  Add the x-smoltbot-agent header to your API calls:\n`);
    console.log(`    x-smoltbot-agent: ${name}\n`);
    if (selectedProvider === "anthropic") {
      console.log(`  Python:     client = Anthropic(base_url="${config.gateway}/anthropic",`);
      console.log(`                  default_headers={"x-smoltbot-agent": "${name}"})`);
      console.log(`  TypeScript: new Anthropic({ baseURL: "${config.gateway}/anthropic",`);
      console.log(`                  defaultHeaders: { "x-smoltbot-agent": "${name}" } })`);
    } else if (selectedProvider === "openai") {
      console.log(`  Python:     client = OpenAI(base_url="${config.gateway}/openai/v1",`);
      console.log(`                  default_headers={"x-smoltbot-agent": "${name}"})`);
      console.log(`  TypeScript: new OpenAI({ baseURL: "${config.gateway}/openai/v1",`);
      console.log(`                  defaultHeaders: { "x-smoltbot-agent": "${name}" } })`);
    } else {
      console.log(`  Add header: x-smoltbot-agent: ${name}`);
      console.log(`  Endpoint:   ${config.gateway}/gemini/v1beta/models/{model}:generateContent`);
    }
  }

  console.log();
  console.log(`  smoltbot status --agent ${name}    Check status`);
  console.log(`  smoltbot agents                    List all agents`);
  console.log();
  console.log(`  Dashboard: ${DASHBOARD_URL}/agents/${agentId}\n`);
}

// ============================================================================
// Gateway verification
// ============================================================================

interface GatewayTestResult {
  ok: boolean;
  response?: string;
  authError?: boolean;
  error?: string;
}

const HELLO_PROMPT = "Say hello in one short sentence. Keep it under 15 words.";

/**
 * Make a real API call through the gateway to verify the key,
 * create the agent on the server, and return the first response.
 */
async function testGatewayCall(
  gateway: string,
  agentName: string,
  provider: Provider,
  apiKey: string,
  mnemomApiKey?: string,
): Promise<GatewayTestResult> {
  const agentHeader = { "x-smoltbot-agent": agentName };

  try {
    let url: string;
    let headers: Record<string, string>;
    let body: string;

    if (provider === "anthropic") {
      url = `${gateway}/anthropic/v1/messages`;
      headers = {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
        ...agentHeader,
        ...(mnemomApiKey ? { "x-mnemom-api-key": mnemomApiKey } : {}),
      };
      body = JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 16000,
        messages: [{ role: "user", content: HELLO_PROMPT }],
      });
    } else if (provider === "openai") {
      url = `${gateway}/openai/v1/chat/completions`;
      headers = {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
        ...agentHeader,
        ...(mnemomApiKey ? { "x-mnemom-api-key": mnemomApiKey } : {}),
      };
      body = JSON.stringify({
        model: "gpt-4o-mini",
        max_tokens: 150,
        messages: [{ role: "user", content: HELLO_PROMPT }],
      });
    } else {
      // Gemini
      url = `${gateway}/gemini/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
      headers = {
        "Content-Type": "application/json",
        ...agentHeader,
        ...(mnemomApiKey ? { "x-mnemom-api-key": mnemomApiKey } : {}),
      };
      body = JSON.stringify({
        contents: [{ parts: [{ text: HELLO_PROMPT }] }],
        generationConfig: { maxOutputTokens: 150 },
      });
    }

    const response = await fetch(url, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(30000),
    });

    if (response.status === 401 || response.status === 403) {
      return { ok: false, authError: true, error: "API key is invalid or revoked" };
    }

    if (response.status === 429) {
      return { ok: true, response: "(rate limited — but key is valid)" };
    }

    if (!response.ok) {
      const errorBody = await response.text().catch(() => "");
      return { ok: false, error: `HTTP ${response.status}: ${errorBody.slice(0, 200)}` };
    }

    // Extract response text from provider-specific format
    const data = await response.json();
    const text = extractResponseText(data, provider);
    return { ok: true, response: text || "(empty response)" };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (message.includes("abort") || message.includes("timeout")) {
      return { ok: false, error: "request timed out (30s)" };
    }
    return { ok: false, error: message };
  }
}

function extractResponseText(data: any, provider: Provider): string | null {
  if (provider === "anthropic") {
    // { content: [{ type: "text", text: "..." }] }
    const blocks = data?.content;
    if (Array.isArray(blocks)) {
      for (const block of blocks) {
        if (block.type === "text" && block.text) return block.text.trim();
      }
    }
  } else if (provider === "openai") {
    // { choices: [{ message: { content: "..." } }] }
    return data?.choices?.[0]?.message?.content?.trim() || null;
  } else {
    // Gemini: { candidates: [{ content: { parts: [{ text: "..." }] } }] }
    return data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || null;
  }
  return null;
}

function openUrl(url: string): void {
  const cmd = process.platform === "darwin"
    ? `open "${url}"`
    : process.platform === "win32"
      ? `start "${url}"`
      : `xdg-open "${url}"`;
  exec(cmd, () => {});
}
