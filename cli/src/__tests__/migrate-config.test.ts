import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { makeMigrateConfigCommand } from "../commands/migrate-config.js";

// The migrate-config command is now a stub (UC-9).
// These tests verify the stub prints the right message.

describe("migrate-config command (removed)", () => {
  beforeEach(() => {
    vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("should print removal notice about automatic migration", async () => {
    const cmd = makeMigrateConfigCommand();
    await cmd.parseAsync(["migrate-config"], { from: "user" });

    expect(vi.mocked(console.error)).toHaveBeenCalledWith(
      expect.stringContaining("migrate-config")
    );
    expect(vi.mocked(console.error)).toHaveBeenCalledWith(
      expect.stringContaining("automatically")
    );
  });
});
