import {
  configExists,
  loadConfig,
  saveConfig,
  generateAgentId,
  deriveAgentId,
  type Config,
} from "../lib/config.js";
import {
  detectOpenClaw,
  detectProviders,
  configureSmoltbotProviders,
  configureSmoltbotProviderForType,
  setDefaultModel,
  getCurrentModel,
  PROVIDER_CONFIG_KEYS,
  type Provider,
  type ModelDefinition,
  type ProviderDetectionResult,
} from "../lib/openclaw.js";
import {
  detectProvider,
  getModelDefinition,
  isAnthropicModel,
  formatModelName,
  MODEL_REGISTRY,
  getLatestModels,
} from "../lib/models.js";
import { refreshModelCache } from "../lib/model-cache.js";
import { askYesNo, askInput, askMultiSelect, askSelect, isInteractive } from "../lib/prompt.js";
import { fmt } from "../lib/format.js";

const GATEWAY_URL = "https://gateway.mnemom.ai";
const DASHBOARD_URL = "https://mnemom.ai";

export interface InitOptions {
  yes?: boolean; // Skip confirmation prompts
  force?: boolean; // Force reconfiguration even if already configured
  openclaw?: boolean; // Force OpenClaw mode
  standalone?: boolean; // Force standalone mode
}

// ============================================================================
// Entry point — dispatches to OpenClaw or standalone flow
// ============================================================================

export async function initCommand(options: InitOptions = {}): Promise<void> {
  console.log(fmt.header("smoltbot init - Transparent AI Agent Tracing"));
  console.log();

  // Step 1: Check for existing smoltbot config
  const existingConfig = await handleExistingConfig(options);
  if (existingConfig === "abort") {
    return;
  }

  // Step 2: Determine mode
  if (options.openclaw) {
    // Explicit --openclaw: run OpenClaw flow, fail if not installed
    return openclawFlow(options, existingConfig);
  }

  if (options.standalone) {
    // Explicit --standalone: skip OpenClaw entirely
    return standaloneFlow(options, existingConfig);
  }

  // No flags: detect OpenClaw and prompt if found
  const detection = detectProviders();

  if (detection.installed && isInteractive()) {
    const choice = await askSelect(
      "OpenClaw detected. Configure for OpenClaw or standalone?",
      ["OpenClaw (use existing API keys from OpenClaw)", "Standalone (enter API keys directly)"],
    );

    if (choice && choice.startsWith("Standalone")) {
      return standaloneFlow(options, existingConfig);
    }
    // Default to OpenClaw if selected or null
    return openclawFlowWithDetection(options, existingConfig, detection);
  }

  if (detection.installed) {
    // Non-interactive with OpenClaw detected: use OpenClaw
    return openclawFlowWithDetection(options, existingConfig, detection);
  }

  // No OpenClaw: go straight to standalone
  return standaloneFlow(options, existingConfig);
}

// ============================================================================
// Standalone flow — prompt for API keys directly
// ============================================================================

const PROVIDER_LABELS: Record<Provider, string> = {
  anthropic: "Anthropic",
  openai: "OpenAI",
  gemini: "Gemini",
};

const KEY_FORMAT_PREFIXES: Record<Provider, { prefix: string; description: string }> = {
  anthropic: { prefix: "sk-ant-", description: "starts with sk-ant-" },
  openai: { prefix: "sk-", description: "starts with sk-" },
  gemini: { prefix: "AIza", description: "starts with AIza" },
};

// Gateway route patterns (from gateway/src/index.ts):
//   /anthropic/* → handleProviderProxy(..., 'anthropic')
//   /openai/*   → handleProviderProxy(..., 'openai')
//   /gemini/*   → handleProviderProxy(..., 'gemini')
const GATEWAY_BASE_URLS: Record<Provider, string> = {
  anthropic: `${GATEWAY_URL}/anthropic`,
  openai: `${GATEWAY_URL}/openai/v1`,
  gemini: `${GATEWAY_URL}/gemini`,
};

async function standaloneFlow(
  options: InitOptions,
  existingConfig: Config | null,
): Promise<void> {
  console.log("Standalone setup (no OpenClaw required)\n");

  // Step 1: Select providers
  let selectedProviderNames: string[];

  if (!isInteractive()) {
    console.log("Non-interactive mode: configuring all providers.\n");
    selectedProviderNames = ["Anthropic", "OpenAI", "Gemini"];
  } else {
    selectedProviderNames = await askMultiSelect(
      "Which providers do you want to configure?",
      ["Anthropic", "OpenAI", "Gemini"],
    );
  }

  if (selectedProviderNames.length === 0) {
    console.log("\nNo providers selected. At least one provider is required.\n");
    process.exit(1);
  }

  // Map display names back to Provider type
  const nameToProvider: Record<string, Provider> = {
    Anthropic: "anthropic",
    OpenAI: "openai",
    Gemini: "gemini",
  };
  const selectedProviders = selectedProviderNames.map((n) => nameToProvider[n]).filter(Boolean);

  console.log();

  // Step 2: Prompt for API key for each selected provider
  const verifiedProviders: { provider: Provider; apiKey: string }[] = [];

  for (const provider of selectedProviders) {
    const label = PROVIDER_LABELS[provider];
    const format = KEY_FORMAT_PREFIXES[provider];

    let apiKey = "";
    let valid = false;

    while (!valid) {
      if (isInteractive()) {
        apiKey = await askInput(`${label} API key (${format.description}):`, true);
      } else {
        // Non-interactive: read from env
        const envVarMap: Record<Provider, string> = {
          anthropic: "ANTHROPIC_API_KEY",
          openai: "OPENAI_API_KEY",
          gemini: "GEMINI_API_KEY",
        };
        apiKey = process.env[envVarMap[provider]] || "";
        if (!apiKey) {
          console.log(`  ${label}: No API key in ${envVarMap[provider]}, skipping`);
          break;
        }
      }

      if (!apiKey) {
        console.log(`  Skipping ${label} (no key entered)\n`);
        break;
      }

      // Validate format
      if (!apiKey.startsWith(format.prefix)) {
        console.log(`  ${fmt.error(`Invalid format: expected key ${format.description}`)}`);
        if (!isInteractive()) break;
        console.log("  Try again.\n");
        continue;
      }

      // Verify with test API call
      console.log(`  Verifying ${label} API key...`);
      const verification = await verifyProviderApiKey(provider, apiKey);
      if (!verification.valid) {
        console.log(`  ${fmt.error(verification.error || "Verification failed")}`);
        if (!isInteractive()) break;
        console.log("  Try again.\n");
        continue;
      }

      console.log(`  ${fmt.success(`${label} API key verified`)}\n`);
      verifiedProviders.push({ provider, apiKey });
      valid = true;
    }
  }

  if (verifiedProviders.length === 0) {
    console.log(fmt.error("No valid API keys configured") + "\n");
    console.log("At least one provider is required. Run smoltbot init again.\n");
    process.exit(1);
  }

  // Step 3: Prompt for optional Mnemom API key (billing identity)
  const mnemomApiKey = await promptMnemomApiKey(existingConfig);

  // Step 4: Create config
  const firstApiKey = verifiedProviders[0].apiKey;
  const existingDefaultAgent = existingConfig?.agents?.[existingConfig.defaultAgent];
  const agentId = firstApiKey
    ? deriveAgentId(firstApiKey)
    : existingDefaultAgent?.agentId || generateAgentId();

  const providerNames = verifiedProviders.map((p) => p.provider);

  const existingV2 = loadConfig();
  const config: Config = {
    version: 2,
    defaultAgent: "default",
    gateway: GATEWAY_URL,
    ...(mnemomApiKey ? { mnemomApiKey } : {}),
    ...(existingV2?.licenseJwt ? { licenseJwt: existingV2.licenseJwt } : {}),
    agents: {
      ...(existingV2?.agents ?? {}),
      default: {
        agentId,
        openclawConfigured: false,
        providers: providerNames,
        configuredAt: new Date().toISOString(),
      },
    },
  };

  saveConfig(config);
  console.log(fmt.success("Created ~/.smoltbot/config.json") + "\n");

  // Step 5: Show success + setup instructions
  showStandaloneSuccess(agentId, verifiedProviders, mnemomApiKey);
}

/**
 * Show standalone success message with SDK snippets per verified provider.
 */
function showStandaloneSuccess(
  agentId: string,
  verifiedProviders: { provider: Provider; apiKey: string }[],
  mnemomApiKey?: string,
): void {
  console.log(fmt.header("smoltbot initialized successfully!"));
  console.log();

  console.log(fmt.label("Agent ID:", agentId) + "\n");

  console.log("Verified providers:");
  for (const { provider } of verifiedProviders) {
    console.log(`  ${fmt.success(PROVIDER_LABELS[provider])}`);
  }
  if (mnemomApiKey) {
    console.log(`  ${fmt.success("Mnemom API key configured")}`);
  }
  console.log();

  console.log(fmt.section("Configure your agent to use the gateway"));
  console.log();

  if (mnemomApiKey) {
    console.log("  Set your Mnemom API key as an environment variable:\n");
    console.log(`    export MNEMOM_API_KEY=<your-mnemom-api-key>\n`);
  }

  for (const { provider } of verifiedProviders) {
    const label = PROVIDER_LABELS[provider];
    const baseUrl = GATEWAY_BASE_URLS[provider];

    console.log(`  ${label}:`);

    if (provider === "anthropic") {
      if (mnemomApiKey) {
        console.log(`    Python:`);
        console.log(`      client = Anthropic(`);
        console.log(`          base_url="${baseUrl}",`);
        console.log(`          default_headers={"x-mnemom-api-key": os.environ["MNEMOM_API_KEY"]}`);
        console.log(`      )`);
        console.log(`    TypeScript:`);
        console.log(`      new Anthropic({`);
        console.log(`          baseURL: "${baseUrl}",`);
        console.log(`          defaultHeaders: { "x-mnemom-api-key": process.env.MNEMOM_API_KEY }`);
        console.log(`      })`);
      } else {
        console.log(`    Python:     client = Anthropic(base_url="${baseUrl}")`);
        console.log(`    TypeScript: new Anthropic({ baseURL: "${baseUrl}" })`);
      }
      console.log(`    Env var:    export ANTHROPIC_BASE_URL=${baseUrl}`);
    } else if (provider === "openai") {
      if (mnemomApiKey) {
        console.log(`    Python:`);
        console.log(`      client = OpenAI(`);
        console.log(`          base_url="${baseUrl}",`);
        console.log(`          default_headers={"x-mnemom-api-key": os.environ["MNEMOM_API_KEY"]}`);
        console.log(`      )`);
        console.log(`    TypeScript:`);
        console.log(`      new OpenAI({`);
        console.log(`          baseURL: "${baseUrl}",`);
        console.log(`          defaultHeaders: { "x-mnemom-api-key": process.env.MNEMOM_API_KEY }`);
        console.log(`      })`);
      } else {
        console.log(`    Python:     client = OpenAI(base_url="${baseUrl}")`);
        console.log(`    TypeScript: new OpenAI({ baseURL: "${baseUrl}" })`);
      }
      console.log(`    Env var:    export OPENAI_BASE_URL=${baseUrl}`);
    } else if (provider === "gemini") {
      console.log(`    REST:       POST ${baseUrl}/v1beta/models/{model}:generateContent`);
      if (mnemomApiKey) {
        console.log(`    Header:     x-mnemom-api-key: $MNEMOM_API_KEY`);
      }
      console.log(`    Env var:    export GEMINI_BASE_URL=${baseUrl}`);
    }
    console.log();
  }

  console.log("Your provider API key is passed through to the provider via the gateway.");
  if (mnemomApiKey) {
    console.log("Your Mnemom API key identifies your billing account for quota tracking.");
  }
  console.log("The gateway traces requests for transparency — no keys are stored.\n");

  console.log(`Your traces will appear at:\n`);
  console.log(`  ${DASHBOARD_URL}/agents/${agentId}\n`);

  console.log(fmt.section("Link to your Mnemom account"));
  console.log();
  console.log("  Sign in (or create a free account) to see your agent's");
  console.log("  traces and manage its alignment card.\n");
  console.log(`  ${DASHBOARD_URL}/claim/${agentId}\n`);

  console.log(fmt.section("Useful commands"));
  console.log("\n  smoltbot status        - Check configuration and connectivity");
  console.log("  smoltbot logs          - View recent traces");
  console.log("  smoltbot integrity     - View integrity score");
  console.log("  smoltbot register <n>  - Register additional named agents");
  console.log("  smoltbot agents        - List all registered agents\n");
}

// ============================================================================
// OpenClaw flow — existing behavior (unchanged)
// ============================================================================

/**
 * OpenClaw flow entry: detects OpenClaw, fails if not installed.
 */
async function openclawFlow(
  options: InitOptions,
  existingConfig: Config | null,
): Promise<void> {
  console.log("Detecting OpenClaw installation...\n");
  const detection = detectProviders();

  if (!detection.installed) {
    console.log(fmt.error("OpenClaw not found") + "\n");
    console.log(detection.error || "OpenClaw is not installed.");
    console.log("\nInstall OpenClaw first: https://openclaw.ai\n");
    process.exit(1);
  }

  return openclawFlowWithDetection(options, existingConfig, detection);
}

/**
 * OpenClaw flow with pre-detected result. This is the original initCommand logic.
 */
async function openclawFlowWithDetection(
  options: InitOptions,
  existingConfig: Config | null,
  detection: ProviderDetectionResult,
): Promise<void> {
  console.log(fmt.success("OpenClaw installation detected") + "\n");

  // Scan all providers for API keys
  const availableProviders: { provider: Provider; apiKey: string }[] = [];

  for (const provider of ["anthropic", "openai", "gemini"] as Provider[]) {
    const info = detection.providers[provider];
    if (info.isOAuth) {
      console.log(`  ${PROVIDER_LABELS[provider]}: OAuth detected (not supported, skipping)`);
    } else if (info.invalidFormat) {
      console.log(`  ${PROVIDER_LABELS[provider]}: Invalid API key format (skipping)`);
    } else if (info.hasApiKey && info.apiKey) {
      console.log(fmt.success(`${PROVIDER_LABELS[provider]} API key found`));
      availableProviders.push({ provider, apiKey: info.apiKey });
    } else {
      console.log(`  ${PROVIDER_LABELS[provider]}: No API key found`);
    }
  }
  console.log();

  // Require at least one provider
  if (availableProviders.length === 0) {
    console.log(fmt.error("No provider API keys found") + "\n");
    console.log("smoltbot requires at least one provider API key.");
    console.log("Configure API keys in OpenClaw:\n");
    console.log("  Anthropic: https://console.anthropic.com/settings/keys");
    console.log("  OpenAI:    https://platform.openai.com/api-keys");
    console.log("  Gemini:    https://aistudio.google.com/apikey\n");
    console.log("Then run `openclaw auth` to add your key(s).\n");
    process.exit(1);
  }

  console.log(`  ${availableProviders.length} provider(s) with API keys\n`);

  // Verify each provider's API key
  const verifiedProviders: { provider: Provider; apiKey: string }[] = [];

  for (const { provider, apiKey } of availableProviders) {
    console.log(`Verifying ${PROVIDER_LABELS[provider]} API key...`);
    const verification = await verifyProviderApiKey(provider, apiKey);
    if (!verification.valid) {
      console.log(`  ${fmt.error(`${verification.error} (skipping ${PROVIDER_LABELS[provider]})`)}\n`);
    } else {
      console.log(fmt.success(`${PROVIDER_LABELS[provider]} API key verified`) + "\n");
      verifiedProviders.push({ provider, apiKey });
    }
  }

  if (verifiedProviders.length === 0) {
    console.log(fmt.error("No valid API keys found") + "\n");
    console.log("All detected API keys failed verification.");
    console.log("Check your API keys and try again.\n");
    process.exit(1);
  }

  // Detect current model
  const { modelId, provider: currentProvider } = parseCurrentModel(detection);

  if (!modelId) {
    console.log(fmt.error("No default model configured in OpenClaw") + "\n");
    console.log("Configure a default model first:");
    console.log("  openclaw models set anthropic/claude-opus-4-5-20251101\n");
    process.exit(1);
  }

  console.log(fmt.success(`Current model: ${currentProvider}/${modelId}`));
  console.log(`  (${formatModelName(modelId)})\n`);

  // Determine models to add per provider
  const verifiedProviderSet = new Set(verifiedProviders.map((p) => p.provider));
  const modelsPerProvider = determineModelsToAdd(modelId, detection, verifiedProviderSet);

  console.log("Models to configure for smoltbot providers:");
  for (const [provider, models] of Object.entries(modelsPerProvider) as [Provider, ModelDefinition[]][]) {
    if (models.length === 0) continue;
    const configKey = PROVIDER_CONFIG_KEYS[provider];
    for (const model of models) {
      console.log(`  - ${configKey}/${model.id} (${model.name})`);
    }
  }
  console.log();

  // Configure all providers that have verified keys
  const alreadyConfigured = detection.smoltbotConfiguredProviders;
  if (alreadyConfigured.length > 0 && !options.force) {
    const configuredNames = alreadyConfigured.map((p) => PROVIDER_LABELS[p]).join(", ");
    console.log(fmt.warn(`smoltbot already configured for: ${configuredNames}`) + "\n");
    if (isInteractive() && !options.yes) {
      const reconfigure = await askYesNo("Reconfigure smoltbot providers?", true);
      if (!reconfigure) {
        console.log("\nKeeping existing configuration.\n");
        const mnemomKey = await promptMnemomApiKey(existingConfig);
        const firstApiKey = verifiedProviders[0]?.apiKey;
        const agentId = await createSmoltbotConfig(existingConfig, firstApiKey, mnemomKey);
        showOpenClawSuccessMessage(agentId, modelId, currentProvider, verifiedProviders.map((p) => p.provider), modelsPerProvider);
        return;
      }
    }
    console.log("Reconfiguring smoltbot providers...\n");
  }

  console.log("Configuring smoltbot providers in OpenClaw...");

  const providerKeys: Partial<Record<Provider, { apiKey: string; models: ModelDefinition[] }>> = {};
  for (const { provider, apiKey } of verifiedProviders) {
    const models = modelsPerProvider[provider] || [];
    if (models.length > 0) {
      providerKeys[provider] = { apiKey, models };
    }
  }

  const configuredProviders = configureSmoltbotProviders(providerKeys);
  for (const provider of configuredProviders) {
    console.log(fmt.success(`${PROVIDER_LABELS[provider]} provider configured (${PROVIDER_CONFIG_KEYS[provider]})`));
  }
  console.log();

  // Offer to switch default model
  const modelProvider = detectProvider(modelId);
  const smoltbotConfigKey = modelProvider ? PROVIDER_CONFIG_KEYS[modelProvider] : PROVIDER_CONFIG_KEYS.anthropic;
  const smoltbotModelPath = `${smoltbotConfigKey}/${modelId}`;
  const alreadyUsingSmoltbot = currentProvider !== null &&
    Object.values(PROVIDER_CONFIG_KEYS).includes(currentProvider);

  let shouldSwitch = false;
  if (!alreadyUsingSmoltbot) {
    shouldSwitch = await promptModelSwitch(
      modelId,
      currentProvider,
      smoltbotModelPath,
      configuredProviders,
      modelsPerProvider,
      options
    );

    if (shouldSwitch) {
      console.log(`Setting default model to ${smoltbotModelPath}...`);
      setDefaultModel(smoltbotModelPath);
      console.log(fmt.success(`Default model set to ${smoltbotModelPath}`) + "\n");
    } else {
      console.log(`Default model unchanged (${currentProvider}/${modelId})\n`);
      console.log("To enable traced mode later:");
      console.log(`  openclaw models set ${smoltbotModelPath}\n`);
    }
  }

  // Prompt for optional Mnemom API key
  const mnemomApiKey = await promptMnemomApiKey(existingConfig);

  // Create smoltbot config
  const firstApiKey = verifiedProviders[0]?.apiKey;
  const agentId = await createSmoltbotConfig(existingConfig, firstApiKey, mnemomApiKey);

  // Show success
  const tracedModeActive = shouldSwitch || alreadyUsingSmoltbot;
  showOpenClawSuccessMessage(agentId, modelId, currentProvider, configuredProviders, modelsPerProvider, tracedModeActive);

  // Trigger model cache refresh in background
  refreshModelCache().catch(() => {});
}

// ============================================================================
// Shared helpers
// ============================================================================

/**
 * Prompt for optional Mnemom platform API key (billing identity).
 * The key is created at mnemom.ai/settings/api-keys and sent as
 * x-mnemom-api-key header to the gateway for quota/billing tracking.
 */
async function promptMnemomApiKey(existingConfig: Config | null): Promise<string | undefined> {
  console.log(fmt.section("Mnemom API Key (optional)"));
  console.log();
  console.log("If you have a paid plan, enter your Mnemom API key");
  console.log("for gateway billing and quota tracking.");
  console.log(`Create one at: ${DASHBOARD_URL}/settings/api-keys\n`);

  if (existingConfig?.mnemomApiKey) {
    console.log(`  Existing key: [CONFIGURED]\n`);
  }

  if (!isInteractive()) {
    const envKey = process.env.MNEMOM_API_KEY || "";
    if (envKey && envKey.startsWith("mnm_")) {
      console.log(`  ${fmt.success("Mnemom API key found in MNEMOM_API_KEY")}\n`);
      return envKey;
    }
    console.log("  No MNEMOM_API_KEY env var found, skipping.\n");
    return existingConfig?.mnemomApiKey;
  }

  const key = await askInput("Mnemom API key (mnm_..., or press Enter to skip):", true);

  if (!key) {
    console.log("  Skipped (free tier or configure later)\n");
    return existingConfig?.mnemomApiKey;
  }

  if (!key.startsWith("mnm_")) {
    console.log(`  ${fmt.error("Invalid format: Mnemom API keys start with mnm_")}`);
    console.log("  Skipping. You can add it later in ~/.smoltbot/config.json\n");
    return existingConfig?.mnemomApiKey;
  }

  console.log(`  ${fmt.success("Mnemom API key configured")}\n`);
  return key;
}

/**
 * Handle existing smoltbot config.
 * Returns "abort" if user doesn't want to reconfigure, or the existing config.
 */
async function handleExistingConfig(
  options: InitOptions
): Promise<Config | null | "abort"> {
  if (!configExists()) {
    return null;
  }

  const existingConfig = loadConfig();
  if (!existingConfig) {
    return null;
  }

  console.log("smoltbot is already initialized.\n");
  console.log(fmt.label("  Gateway:", ` ${existingConfig.gateway || GATEWAY_URL}`));
  console.log();

  // Show registered agents
  const agentNames = Object.keys(existingConfig.agents);
  console.log("  Registered agents:");
  for (const name of agentNames) {
    const agent = existingConfig.agents[name];
    const isDefault = name === existingConfig.defaultAgent;
    const marker = isDefault ? " (default)" : "";
    console.log(`    ${name}${marker} — ${agent.agentId}`);
  }
  console.log();

  console.log("  To add another agent:");
  console.log("    smoltbot register <name>\n");

  if (options.force) {
    console.log("Reconfiguring (--force)...\n");
    return existingConfig;
  }

  return "abort";
}

/**
 * Parse the current model from detection results.
 */
function parseCurrentModel(detection: ProviderDetectionResult): {
  modelId: string | null;
  provider: string | null;
} {
  let modelId = detection.currentModelId || null;
  let provider = detection.currentProvider || null;

  if (provider && Object.values(PROVIDER_CONFIG_KEYS).includes(provider)) {
    // Already using a smoltbot provider
  } else if (!provider && modelId) {
    const detected = detectProvider(modelId);
    provider = detected || "anthropic";
  }

  return { modelId, provider };
}

/**
 * Determine which models to add per provider.
 */
function determineModelsToAdd(
  currentModelId: string,
  detection: ProviderDetectionResult,
  verifiedProviders: Set<Provider>
): Record<Provider, ModelDefinition[]> {
  const result: Record<Provider, ModelDefinition[]> = {
    anthropic: [],
    openai: [],
    gemini: [],
  };

  const latestModels = getLatestModels();

  for (const provider of verifiedProviders) {
    const addedIds = new Set<string>();
    const models: ModelDefinition[] = [];

    const currentModelProvider = detectProvider(currentModelId);
    if (currentModelProvider === provider) {
      const modelDef = getModelDefinition(currentModelId);
      models.push(modelDef);
      addedIds.add(currentModelId);
    }

    for (const model of latestModels[provider]) {
      if (!addedIds.has(model.id)) {
        models.push(model);
        addedIds.add(model.id);
      }
    }

    result[provider] = models;
  }

  return result;
}

/**
 * Prompt user to switch default model (OpenClaw flow only).
 */
async function promptModelSwitch(
  modelId: string,
  currentProvider: string | null,
  smoltbotModelPath: string,
  configuredProviders: Provider[],
  modelsPerProvider: Record<Provider, ModelDefinition[]>,
  options: InitOptions
): Promise<boolean> {
  if (options.yes) return true;
  if (!isInteractive()) return true;

  console.log(fmt.section("Switch to traced mode now?"));
  console.log();
  console.log(`  Current:  ${currentProvider}/${modelId}`);
  console.log(`  Traced:   ${smoltbotModelPath}\n`);
  console.log("When using smoltbot models, all API calls are logged for");
  console.log("transparency and alignment verification.\n");

  if (configuredProviders.length > 1) {
    console.log("Available traced models across providers:");
    for (const provider of configuredProviders) {
      const models = modelsPerProvider[provider] || [];
      if (models.length > 0) {
        const configKey = PROVIDER_CONFIG_KEYS[provider];
        console.log(`  ${PROVIDER_LABELS[provider]}:`);
        for (const model of models) {
          console.log(`    openclaw models set ${configKey}/${model.id}`);
        }
      }
    }
    console.log();
  }

  return askYesNo("Switch to traced model?", true);
}

/**
 * Create or update smoltbot config (OpenClaw flow).
 */
async function createSmoltbotConfig(
  existingConfig: Config | null,
  apiKey?: string,
  mnemomApiKey?: string,
): Promise<string> {
  const defaultAgent = existingConfig?.agents?.[existingConfig.defaultAgent];
  const agentId = apiKey
    ? deriveAgentId(apiKey)
    : defaultAgent?.agentId || generateAgentId();

  const existingV2 = loadConfig();
  const config: Config = {
    version: 2,
    defaultAgent: "default",
    gateway: GATEWAY_URL,
    ...(mnemomApiKey ? { mnemomApiKey } : {}),
    ...(existingV2?.licenseJwt ? { licenseJwt: existingV2.licenseJwt } : {}),
    agents: {
      ...(existingV2?.agents ?? {}),
      default: {
        agentId,
        openclawConfigured: true,
        configuredAt: new Date().toISOString(),
      },
    },
  };

  saveConfig(config);
  console.log(fmt.success("Created ~/.smoltbot/config.json") + "\n");

  return agentId;
}

/**
 * Show success message for OpenClaw flow.
 */
function showOpenClawSuccessMessage(
  agentId: string,
  modelId: string,
  currentProvider: string | null,
  configuredProviders: Provider[],
  modelsPerProvider: Record<Provider, ModelDefinition[]>,
  switched: boolean = true
): void {
  console.log(fmt.header("smoltbot initialized successfully!"));
  console.log();

  console.log(fmt.label("Agent ID:", agentId) + "\n");

  console.log("Configured providers:");
  for (const provider of configuredProviders) {
    const configKey = PROVIDER_CONFIG_KEYS[provider];
    const models = modelsPerProvider[provider] || [];
    const modelNames = models.map((m) => m.name).join(", ");
    console.log(`  ${fmt.success(`${PROVIDER_LABELS[provider]} (${configKey}) — ${modelNames}`)}`);
  }
  console.log();

  if (switched) {
    console.log(fmt.success("Traced mode is now active") + "\n");
    console.log("All OpenClaw API calls will be traced. Your traces will");
    console.log("appear at:\n");
  } else {
    console.log("Traced mode is ready but not active.\n");
    const modelProvider = detectProvider(modelId);
    const tracedConfigKey = modelProvider ? PROVIDER_CONFIG_KEYS[modelProvider] : PROVIDER_CONFIG_KEYS.anthropic;
    console.log("To enable traced mode, run:");
    console.log(`  openclaw models set ${tracedConfigKey}/${modelId}\n`);
    console.log("Once enabled, your traces will appear at:\n");
  }

  console.log(`  ${DASHBOARD_URL}/agents/${agentId}\n`);

  console.log(fmt.section("Link to your Mnemom account"));
  console.log();
  console.log("  Sign in (or create a free account) to see your agent's");
  console.log("  traces and manage its alignment card.\n");
  console.log(`  ${DASHBOARD_URL}/claim/${agentId}\n`);

  console.log(fmt.section("Useful commands"));
  console.log("\n  smoltbot status        - Check configuration and connectivity");
  console.log("  smoltbot logs          - View recent traces");
  console.log("  smoltbot integrity     - View integrity score");
  console.log("  smoltbot register <n>  - Register additional named agents");
  console.log("  smoltbot agents        - List all registered agents\n");

  console.log(fmt.section("Switch between traced and untraced mode"));
  console.log();

  for (const provider of configuredProviders) {
    const configKey = PROVIDER_CONFIG_KEYS[provider];
    const models = modelsPerProvider[provider] || [];
    if (models.length > 0) {
      const firstModel = models[0];
      console.log(`  Traced (${PROVIDER_LABELS[provider]}):   openclaw models set ${configKey}/${firstModel.id}`);
      console.log(`  Untraced (${PROVIDER_LABELS[provider]}): openclaw models set ${provider}/${firstModel.id}`);
    }
  }
  console.log();
}

// ============================================================================
// API key verification (shared by both flows)
// ============================================================================

/**
 * Verify an API key for a given provider.
 * Fail-open: network errors and 5xx responses don't block init.
 */
async function verifyProviderApiKey(
  provider: Provider,
  apiKey: string
): Promise<{ valid: boolean; error?: string }> {
  switch (provider) {
    case "anthropic":
      return verifyAnthropicApiKey(apiKey);
    case "openai":
      return verifyOpenAIApiKey(apiKey);
    case "gemini":
      return verifyGeminiApiKey(apiKey);
    default:
      return { valid: true };
  }
}

async function verifyAnthropicApiKey(apiKey: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: 1,
        messages: [{ role: "user", content: "hi" }],
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok || response.status === 429) {
      return { valid: true };
    }

    if (response.status === 401 || response.status === 403) {
      return {
        valid: false,
        error: "Anthropic API key is invalid or has been revoked.",
      };
    }

    return { valid: true };
  } catch {
    console.log("  Could not verify API key (network error). Proceeding anyway.\n");
    return { valid: true };
  }
}

async function verifyOpenAIApiKey(apiKey: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "gpt-5-mini",
        max_tokens: 1,
        messages: [{ role: "user", content: "hi" }],
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (response.ok || response.status === 429) {
      return { valid: true };
    }

    if (response.status === 401 || response.status === 403) {
      return {
        valid: false,
        error: "OpenAI API key is invalid or has been revoked.",
      };
    }

    return { valid: true };
  } catch {
    console.log("  Could not verify API key (network error). Proceeding anyway.\n");
    return { valid: true };
  }
}

async function verifyGeminiApiKey(apiKey: string): Promise<{ valid: boolean; error?: string }> {
  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          contents: [{ parts: [{ text: "hi" }] }],
          generationConfig: { maxOutputTokens: 1 },
        }),
        signal: AbortSignal.timeout(10000),
      }
    );

    if (response.ok || response.status === 429) {
      return { valid: true };
    }

    if (response.status === 400 || response.status === 401 || response.status === 403) {
      return {
        valid: false,
        error: "Gemini API key is invalid or has been revoked.",
      };
    }

    return { valid: true };
  } catch {
    console.log("  Could not verify API key (network error). Proceeding anyway.\n");
    return { valid: true };
  }
}
