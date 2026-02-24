import * as readline from "node:readline";

/**
 * Ask a yes/no question with a default answer
 * @param question The question to ask
 * @param defaultYes If true, default is Yes (Y/n), otherwise default is No (y/N)
 * @returns Promise<boolean> - true for yes, false for no
 */
export async function askYesNo(
  question: string,
  defaultYes: boolean = true
): Promise<boolean> {
  const suffix = defaultYes ? "[Y/n]" : "[y/N]";

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question(`${question} ${suffix} `, (answer) => {
      rl.close();

      const normalized = answer.trim().toLowerCase();

      if (normalized === "") {
        // Use default
        resolve(defaultYes);
      } else if (normalized === "y" || normalized === "yes") {
        resolve(true);
      } else if (normalized === "n" || normalized === "no") {
        resolve(false);
      } else {
        // Invalid input, use default
        resolve(defaultYes);
      }
    });
  });
}

/**
 * Prompt for a single line of text input.
 * If mask is true, input is hidden (for API keys).
 */
export async function askInput(
  question: string,
  mask: boolean = false
): Promise<string> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  if (mask && process.stdin.isTTY) {
    // Close readline so it doesn't echo characters
    rl.close();

    // Mask input by suppressing echo via raw mode
    process.stdout.write(`${question} `);
    return new Promise((resolve) => {
      let input = "";
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.setEncoding("utf8");
      const onData = (chunk: string) => {
        for (const char of chunk) {
          if (char === "\n" || char === "\r" || char === "\u0004") {
            process.stdin.setRawMode(false);
            process.stdin.pause();
            process.stdin.removeListener("data", onData);
            process.stdout.write("\n");
            resolve(input);
            return;
          } else if (char === "\u007F" || char === "\b") {
            // Backspace
            if (input.length > 0) {
              input = input.slice(0, -1);
              process.stdout.write("\b \b");
            }
          } else if (char === "\u0003") {
            // Ctrl+C
            process.exit(1);
          } else {
            input += char;
            process.stdout.write("*");
          }
        }
      };
      process.stdin.on("data", onData);
    });
  }

  return new Promise((resolve) => {
    rl.question(`${question} `, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

/**
 * Multi-select prompt. Displays numbered options, user enters comma-separated numbers.
 * Returns array of selected labels.
 */
export async function askMultiSelect(
  question: string,
  options: string[]
): Promise<string[]> {
  console.log(`\n${question}`);
  for (let i = 0; i < options.length; i++) {
    console.log(`  ${i + 1}) ${options[i]}`);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question("Select (comma-separated, e.g. 1,2): ", (answer) => {
      rl.close();
      const parts = answer.split(",").map((s) => s.trim());
      const selected: string[] = [];
      for (const part of parts) {
        const idx = parseInt(part, 10) - 1;
        if (idx >= 0 && idx < options.length && !selected.includes(options[idx])) {
          selected.push(options[idx]);
        }
      }
      resolve(selected);
    });
  });
}

/**
 * Single-select prompt. Displays numbered options, user enters a number.
 * Returns selected label or null if invalid.
 */
export async function askSelect(
  question: string,
  options: string[]
): Promise<string | null> {
  console.log(`\n${question}`);
  for (let i = 0; i < options.length; i++) {
    console.log(`  ${i + 1}) ${options[i]}`);
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return new Promise((resolve) => {
    rl.question("Select: ", (answer) => {
      rl.close();
      const idx = parseInt(answer.trim(), 10) - 1;
      if (idx >= 0 && idx < options.length) {
        resolve(options[idx]);
      } else {
        resolve(null);
      }
    });
  });
}

/**
 * Check if running in non-interactive mode (no TTY)
 */
export function isInteractive(): boolean {
  return process.stdin.isTTY === true;
}
