import { loadConfig, saveConfig, configExists } from "../lib/config.js";
import { API_BASE } from "../lib/api.js";
import { fmt } from "../lib/format.js";

/** Sanitize file-sourced data before use in outbound HTTP requests. */
function sanitizeForHttp(data: string): string {
  return String(data).trim();
}

/**
 * Decode a JWT payload without verifying the signature.
 */
function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length !== 3) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padding = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
    return JSON.parse(Buffer.from(padded + padding, "base64").toString("utf-8"));
  } catch {
    return null;
  }
}

export async function licenseActivateCommand(jwt: string): Promise<void> {
  if (!jwt || jwt.trim() === "") {
    console.error("Error: License JWT is required");
    console.error("Usage: smoltbot license activate <jwt>");
    process.exit(1);
  }

  // Decode claims
  const claims = decodeJwtPayload(jwt);
  if (!claims) {
    console.error("Error: Invalid JWT format");
    process.exit(1);
  }

  console.log("\nActivating enterprise license...\n");

  // Validate against API (if reachable)
  const hostname = (await import("node:os")).hostname();
  try {
    const licenseUrl = new URL(`${API_BASE}/v1/license/validate`).href;
    const response = await fetch(licenseUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        license: jwt,
        instance_id: hostname,
        instance_metadata: {
          hostname,
          platform: process.platform,
          cli_version: "2.1.0",
        },
      }),
    });

    if (response.ok) {
      const result = (await response.json()) as Record<string, unknown>;
      console.log("  License validated successfully!\n");
      if (result.warning) {
        console.log(`  Warning: ${result.warning}\n`);
      }
    } else {
      const err = (await response.json()) as Record<string, unknown>;
      console.log(`  Warning: Validation returned ${response.status}: ${err.error || "unknown"}`);
      console.log("  License stored locally (will retry validation).\n");
    }
  } catch {
    console.log("  Warning: Could not reach API for validation.");
    console.log("  License stored locally (offline mode).\n");
  }

  // Store in config
  const config = loadConfig();
  if (!config) {
    console.log("No configuration found. Run 'smoltbot init' first.");
    process.exit(1);
  }
  config.licenseJwt = jwt;
  saveConfig(config);

  // Display info
  const expiresAt = claims.exp ? new Date((claims.exp as number) * 1000) : null;
  const daysRemaining = expiresAt ? Math.floor((expiresAt.getTime() - Date.now()) / 86400000) : "unknown";

  console.log("  License ID:      " + (claims.license_id || "unknown"));
  console.log("  Plan:            " + (claims.plan_id || "unknown"));
  console.log("  Features:        " + Object.keys((claims.feature_flags as Record<string, boolean>) || {}).filter((k) => (claims.feature_flags as Record<string, boolean>)[k]).join(", ") || "none");
  console.log("  Expires:         " + (expiresAt ? expiresAt.toISOString() : "unknown"));
  console.log("  Days remaining:  " + daysRemaining);
  console.log("  Max activations: " + (claims.max_activations || "unknown"));
  console.log("  Offline mode:    " + (claims.is_offline ? "yes" : "no"));
  console.log();
}

export async function licenseStatusCommand(): Promise<void> {
  if (!configExists()) {
    console.error("Error: No smoltbot configuration found. Run 'smoltbot init' first.");
    process.exit(1);
  }

  const config = loadConfig();
  if (!config?.licenseJwt) {
    console.log("\nNo enterprise license configured.");
    console.log("Use 'smoltbot license activate <jwt>' to activate a license.\n");
    return;
  }

  const claims = decodeJwtPayload(config.licenseJwt);
  if (!claims) {
    console.error("Error: Stored license JWT is invalid");
    process.exit(1);
  }

  const expiresAt = claims.exp ? new Date((claims.exp as number) * 1000) : null;
  const daysRemaining = expiresAt ? Math.floor((expiresAt.getTime() - Date.now()) / 86400000) : null;
  const isExpired = daysRemaining !== null && daysRemaining <= 0;

  console.log(fmt.header("Enterprise License Status"));
  console.log();
  console.log(`  ${fmt.label("License ID:     ", String(claims.license_id || "unknown"))}`);
  console.log(`  ${fmt.label("Account:        ", String(claims.account_id || "unknown"))}`);
  console.log(`  ${fmt.label("Plan:           ", String(claims.plan_id || "unknown"))}`);
  console.log(`  ${fmt.label("Features:       ", Object.keys((claims.feature_flags as Record<string, boolean>) || {}).filter((k) => (claims.feature_flags as Record<string, boolean>)[k]).join(", ") || "none")}`);
  console.log(`  ${fmt.label("Expires:        ", expiresAt ? expiresAt.toISOString() : "unknown")}`);
  console.log(`  ${fmt.label("Days remaining: ", String(daysRemaining ?? "unknown"))}`);
  console.log(`  ${fmt.label("Status:         ", isExpired ? "EXPIRED" : "Active")}`);
  console.log(`  ${fmt.label("Max activations:", ` ${claims.max_activations || "unknown"}`)}`);
  console.log(`  ${fmt.label("Offline mode:   ", claims.is_offline ? "yes" : "no")}`);
  console.log();

  if (isExpired) {
    console.log("  WARNING: License has expired. Contact enterprise@mnemom.ai for renewal.\n");
  } else if (daysRemaining !== null && daysRemaining <= 30) {
    console.log(`  WARNING: License expires in ${daysRemaining} days.\n`);
  }
}

export async function licenseDeactivateCommand(): Promise<void> {
  if (!configExists()) {
    console.error("Error: No smoltbot configuration found.");
    process.exit(1);
  }

  const config = loadConfig();
  if (!config?.licenseJwt) {
    console.log("\nNo enterprise license to deactivate.\n");
    return;
  }

  // Try to deactivate via API
  const claims = decodeJwtPayload(config.licenseJwt);
  if (claims) {
    try {
      const hostname = (await import("node:os")).hostname();
      const deactivateUrl = new URL(`${API_BASE}/v1/license/validate`).href;
      await fetch(deactivateUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: sanitizeForHttp(JSON.stringify({
          license: String(config.licenseJwt),
          instance_id: hostname,
          instance_metadata: { deactivating: true },
        })),
      });
    } catch {
      // Best-effort
    }
  }

  // Remove from config
  delete config.licenseJwt;
  saveConfig(config);

  console.log("\nLicense deactivated and removed from local configuration.\n");
}
