import { getGatewayUrl } from "../lib/config.js";
import { resolveAgentId, getAgent, getIntegrity, getTraces } from "../lib/api.js";
import { isLoggedIn, getAuthInfo } from "../lib/auth.js";
import {
  detectOpenClaw,
  detectProviders,
  getCurrentModel,
  getSmoltbotConfiguredProviders,
  PROVIDER_CONFIG_KEYS,
  type Provider,
} from "../lib/openclaw.js";
import { formatModelName, detectProvider } from "../lib/models.js";
import { refreshModelCache } from "../lib/model-cache.js";
import { fmt } from "../lib/format.js";

const DASHBOARD_URL = "https://mnemom.ai";

interface StatusCheckResult {
  name: string;
  status: "ok" | "warning" | "error";
  message: string;
  details?: string;
}

const PROVIDER_LABELS: Record<Provider, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  gemini: "Gemini",
};

const AIP_SUPPORT: Record<Provider, string> = {
  anthropic: "Full (thinking blocks)",
  openai: "Via reasoning summaries",
  gemini: "Full (thought parts)",
};

export async function statusCommand(agentName?: string): Promise<void> {
  console.log(fmt.header("mnemom status"));
  console.log();

  const checks: StatusCheckResult[] = [];

  // 1. Check auth status
  const authCheck = await checkAuthStatus();
  checks.push(authCheck);

  if (authCheck.status === "error") {
    printChecks(checks);
    console.log("\nRun `mnemom login` to authenticate.\n");
    process.exit(1);
  }

  // Resolve agent ID from server
  const agentId = await resolveAgentId(agentName);
  const gatewayUrl = getGatewayUrl();

  // 2. Check OpenClaw configuration
  const openclawCheck = checkOpenClawConfig();
  checks.push(openclawCheck);

  // 3. Check configured providers
  const providerChecks = checkConfiguredProviders();
  checks.push(...providerChecks);

  // 4. Check current model
  const modelCheck = checkCurrentModel();
  checks.push(modelCheck);

  // 5. Test gateway connectivity
  const gatewayCheck = await checkGatewayConnectivity(gatewayUrl);
  checks.push(gatewayCheck);

  // 6. Test API connectivity
  const apiCheck = await checkApiConnectivity(agentId);
  checks.push(apiCheck);

  // Print all checks
  printChecks(checks);

  // Show configuration details
  console.log(fmt.section("Configuration"));
  console.log();

  console.log(fmt.label("Agent ID: ", agentId));
  console.log(fmt.label("Gateway:  ", gatewayUrl));
  console.log(fmt.label("Dashboard:", ` ${DASHBOARD_URL}/agents/${agentId}`));

  // Show current model info
  const { fullPath, provider, modelId } = getCurrentModel();
  if (fullPath) {
    console.log(`\nCurrent Model: ${fullPath}`);
    if (modelId) {
      console.log(`  (${formatModelName(modelId)})`);
    }
    if (provider && (provider === "smoltbot" || provider.startsWith("smoltbot"))) {
      console.log("  Status: Traced mode ACTIVE");
    } else {
      console.log("  Status: Traced mode NOT ACTIVE");
      if (modelId) {
        const detectedProvider = detectProvider(modelId);
        const configKey = detectedProvider ? PROVIDER_CONFIG_KEYS[detectedProvider] : "mnemom";
        console.log(`\n  To enable: openclaw models set ${configKey}/${modelId}`);
      }
    }
  }

  // Show provider summary
  showProviderSummary();

  // Show trace summary if available
  if (apiCheck.status === "ok") {
    await showTraceSummary(agentId);
  }

  // Show overall status
  const hasErrors = checks.some((c) => c.status === "error");
  const hasWarnings = checks.some((c) => c.status === "warning");

  if (hasErrors) {
    console.log("\n" + fmt.header("Status: ISSUES DETECTED"));
    console.log("\n  Fix the errors above to ensure tracing works correctly.\n");
  } else if (hasWarnings) {
    console.log("\n" + fmt.header("Status: OK (with warnings)"));
    console.log();
  } else {
    console.log("\n" + fmt.header("Status: ALL SYSTEMS GO"));
    console.log();
  }

  // Refresh model cache in background (non-blocking)
  refreshModelCache().catch(() => {});
}

async function checkAuthStatus(): Promise<StatusCheckResult> {
  const loggedIn = await isLoggedIn();
  if (!loggedIn) {
    return {
      name: "Authentication",
      status: "error",
      message: "Not authenticated",
      details: "Run `mnemom login` or set MNEMOM_API_KEY",
    };
  }

  const auth = getAuthInfo();
  if (auth) {
    return {
      name: "Authentication",
      status: "ok",
      message: `Logged in as ${auth.email}`,
    };
  }

  // API key auth (no email available)
  return {
    name: "Authentication",
    status: "ok",
    message: "Authenticated via API key",
  };
}

function checkOpenClawConfig(): StatusCheckResult {
  const detection = detectOpenClaw();

  if (!detection.installed) {
    return {
      name: "OpenClaw",
      status: "error",
      message: "Not installed",
      details: "Install from https://openclaw.ai",
    };
  }

  if (!detection.hasApiKey) {
    if (detection.isOAuth) {
      return {
        name: "OpenClaw",
        status: "error",
        message: "OAuth auth (not supported)",
        details: "mnemom requires API key authentication",
      };
    }

    // Check if any provider has a key (not just Anthropic)
    const providerDetection = detectProviders();
    const anyKey = Object.values(providerDetection.providers).some((p) => p.hasApiKey);
    if (anyKey) {
      return {
        name: "OpenClaw",
        status: "ok",
        message: "API key(s) found",
      };
    }

    return {
      name: "OpenClaw",
      status: "error",
      message: "No API keys configured",
      details: "Run `openclaw auth` to add your API key",
    };
  }

  if (!detection.smoltbotAlreadyConfigured) {
    return {
      name: "OpenClaw",
      status: "warning",
      message: "mnemom provider not configured",
      details: "Run `mnemom register <name>` to configure",
    };
  }

  return {
    name: "OpenClaw",
    status: "ok",
    message: "mnemom provider configured",
  };
}

function checkConfiguredProviders(): StatusCheckResult[] {
  const results: StatusCheckResult[] = [];
  const providerDetection = detectProviders();

  if (!providerDetection.installed) return results;

  const configuredProviders = getSmoltbotConfiguredProviders();

  for (const provider of ["anthropic", "openai", "gemini"] as Provider[]) {
    const info = providerDetection.providers[provider];
    const isConfigured = configuredProviders.includes(provider);

    if (info.hasApiKey && isConfigured) {
      results.push({
        name: `${PROVIDER_LABELS[provider]}`,
        status: "ok",
        message: `Configured (AIP: ${AIP_SUPPORT[provider]})`,
      });
    } else if (info.hasApiKey && !isConfigured) {
      results.push({
        name: `${PROVIDER_LABELS[provider]}`,
        status: "warning",
        message: "API key found but not configured",
        details: "Run `mnemom register <name>` to configure",
      });
    }
    // Don't show providers without keys (too noisy)
  }

  return results;
}

function checkCurrentModel(): StatusCheckResult {
  const { fullPath, provider, modelId } = getCurrentModel();

  if (!fullPath) {
    return {
      name: "Current Model",
      status: "warning",
      message: "No default model set",
      details: "Run `openclaw models set mnemom/<model>`",
    };
  }

  if (provider && (provider === "smoltbot" || provider.startsWith("smoltbot"))) {
    return {
      name: "Current Model",
      status: "ok",
      message: `${modelId} (traced)`,
    };
  }

  return {
    name: "Current Model",
    status: "warning",
    message: `${fullPath} (not traced)`,
    details: `Switch with: openclaw models set mnemom/${modelId}`,
  };
}

function showProviderSummary(): void {
  const providerDetection = detectProviders();
  if (!providerDetection.installed) return;

  const configuredProviders = getSmoltbotConfiguredProviders();
  if (configuredProviders.length === 0) return;

  console.log(fmt.section("Configured Providers"));
  console.log();

  for (const provider of configuredProviders) {
    const label = PROVIDER_LABELS[provider];
    const aip = AIP_SUPPORT[provider];
    const configKey = PROVIDER_CONFIG_KEYS[provider];
    console.log(`  ${label}: ${configKey}/* (AIP: ${aip})`);
  }
}

async function checkGatewayConnectivity(gatewayUrl: string): Promise<StatusCheckResult> {
  try {
    const response = await fetch(`${gatewayUrl}/health`, {
      signal: AbortSignal.timeout(5000),
    });

    if (response.ok) {
      const data = (await response.json()) as { status?: string; version?: string };
      return {
        name: "Gateway",
        status: "ok",
        message: `Connected (v${data.version || "unknown"})`,
      };
    }

    return {
      name: "Gateway",
      status: "error",
      message: `HTTP ${response.status}`,
      details: "Gateway returned an error",
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (message.includes("timeout") || message.includes("TIMEOUT")) {
      return {
        name: "Gateway",
        status: "error",
        message: "Connection timeout",
        details: "Check your network connection",
      };
    }

    return {
      name: "Gateway",
      status: "error",
      message: "Connection failed",
      details: message,
    };
  }
}

async function checkApiConnectivity(agentId: string): Promise<StatusCheckResult> {
  try {
    const agent = await getAgent(agentId);

    if (agent) {
      return {
        name: "API",
        status: "ok",
        message: "Agent registered",
      };
    }

    return {
      name: "API",
      status: "warning",
      message: "Agent not yet registered",
      details: "Will register on first traced API call",
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);

    if (message.includes("404") || message.includes("not found")) {
      return {
        name: "API",
        status: "warning",
        message: "Agent not yet registered",
        details: "Will register on first traced API call",
      };
    }

    if (message.includes("timeout") || message.includes("TIMEOUT")) {
      return {
        name: "API",
        status: "error",
        message: "Connection timeout",
        details: "Check your network connection",
      };
    }

    return {
      name: "API",
      status: "error",
      message: "Connection failed",
      details: message,
    };
  }
}

async function showTraceSummary(agentId: string): Promise<void> {
  try {
    const [integrityResult, tracesResult] = await Promise.allSettled([
      getIntegrity(agentId),
      getTraces(agentId, 1),
    ]);

    console.log(fmt.section("Trace Summary"));
    console.log();

    if (integrityResult.status === "fulfilled") {
      const integrity = integrityResult.value;
      // Field names per docs.mnemom.ai IntegrityScore: integrity_score
      // (in [0,1]), verified_traces, violation_count.
      const score = (integrity.integrity_score * 100).toFixed(1);
      console.log(`Integrity Score: ${score}%`);
      console.log(`Total Traces:    ${integrity.total_traces}`);
      console.log(`Verified:        ${integrity.verified_traces}`);
      if (integrity.violation_count > 0) {
        console.log(`Violations:      ${integrity.violation_count}`);
      }
    } else {
      console.log("Integrity: No data yet");
    }

    if (tracesResult.status === "fulfilled" && tracesResult.value.length > 0) {
      const lastTrace = tracesResult.value[0];
      const lastTime = new Date(lastTrace.timestamp).toLocaleString();
      console.log(`\nLast Activity:   ${lastTime}`);
    } else {
      console.log("\nLast Activity:   None");
    }
  } catch {
    // Silently skip if we can't get trace info
  }
}

function printChecks(checks: StatusCheckResult[]): void {
  console.log(fmt.section("System Checks"));
  console.log();

  for (const check of checks) {
    if (check.status === "ok") {
      console.log(fmt.success(`${check.name}: ${check.message}`));
    } else if (check.status === "warning") {
      console.log(fmt.warn(`${check.name}: ${check.message}`));
    } else {
      console.log(fmt.error(`${check.name}: ${check.message}`));
    }
    if (check.details) {
      console.log(`    ${check.details}`);
    }
  }
}
