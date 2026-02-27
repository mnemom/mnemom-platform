import { configExists, getAuthInfo, clearAuthTokens } from "../lib/config.js";
import { login } from "../lib/auth.js";
import { fmt } from "../lib/format.js";
import { askInput } from "../lib/prompt.js";

export async function loginCommand(): Promise<void> {
  if (!configExists()) {
    console.log("\n" + fmt.error("smoltbot is not initialized") + "\n");
    console.log("Run `smoltbot init` to get started.\n");
    process.exit(1);
  }

  const email = await askInput("Email:");
  if (!email) {
    console.log(fmt.error("Email is required."));
    process.exit(1);
  }

  const password = await askInput("Password:", true);
  if (!password) {
    console.log(fmt.error("Password is required."));
    process.exit(1);
  }

  try {
    const tokens = await login(email, password);
    console.log();
    console.log(fmt.success("Logged in successfully!"));
    console.log(fmt.label("  Email:  ", ` ${tokens.email}`));
    console.log(fmt.label("  User ID:", ` ${tokens.userId}`));
    console.log();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("\n" + fmt.error(`Login failed: ${message}`) + "\n");
    process.exit(1);
  }
}

export async function logoutCommand(): Promise<void> {
  clearAuthTokens();
  console.log(fmt.success("Logged out."));
}

export async function whoamiCommand(): Promise<void> {
  const auth = getAuthInfo();

  if (!auth) {
    console.log("\nNot logged in. Run `smoltbot login` to authenticate.\n");
    return;
  }

  const now = Math.floor(Date.now() / 1000);
  const expired = auth.expiresAt <= now;
  const expiresDate = new Date(auth.expiresAt * 1000).toISOString();

  console.log(fmt.header("Auth Status"));
  console.log();
  console.log(fmt.label("  Email:  ", ` ${auth.email}`));
  console.log(fmt.label("  User ID:", ` ${auth.userId}`));
  console.log(
    fmt.label("  Token:  ", expired ? " expired" : ` valid until ${expiresDate}`)
  );
  console.log();
}
