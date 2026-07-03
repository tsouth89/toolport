/**
 * Shell-aware argument parsing and formatting.
 *
 * The server dialog's "Arguments" field is a single text input, but the backend
 * needs a `string[]`. The original code used a naive `.split(/\s+/)` which broke
 * any path containing spaces (e.g. `/Applications/Open Design.app/...`).
 *
 * These functions implement a subset of shell quoting rules — enough to make the
 * UI input → `string[]` → UI input round-trip lossless:
 *
 *   - Whitespace (space, tab, newline) separates args, unless inside quotes.
 *   - Single quotes (`'…'`) make everything literal (no escapes).
 *   - Double quotes (`"…"`) allow `\"` to embed a literal double quote.
 *   - Backslash is only special inside double quotes (as `\"`). Outside quotes
 *     it's a literal character, so Windows paths (`C:\Users\…`) work unquoted.
 *   - Empty quote pairs (`""` or `''`) produce a deliberate empty-string arg.
 *
 * This is intentionally simpler than a full POSIX shell tokenizer (no variable
 * expansion, no command substitution, no `\n`/`\t` escapes). The input comes
 * from a text field in a desktop app, not an untrusted shell.
 */

/**
 * Parse a string of shell-style quoted arguments into an array.
 *
 * Mirrors how a shell would split the input into `argv`, supporting single and
 * double quotes. An empty or whitespace-only input yields `[]`.
 */
export function parseArgs(input: string): string[] {
  const result: string[] = [];
  let current = "";
  let inSingle = false; // Inside single quotes: everything literal until next `'`.
  let inDouble = false; // Inside double quotes: `\"` is an escaped quote.
  let hasContent = false; // Whether `current` has accumulated anything (including from empty quotes).

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];

    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      } else {
        current += ch;
        hasContent = true;
      }
      continue;
    }

    if (inDouble) {
      if (ch === "\\") {
        // Inside double quotes, backslash escapes the next character.
        // Only `\"` and `\\` are meaningful escapes; any other `\x` is
        // passed through as two literal characters (matching the formatter,
        // which only escapes `"` and `\`).
        const next = input[i + 1];
        if (next === '"' || next === "\\") {
          current += next;
          hasContent = true;
          i++; // consume the escaped character
        } else {
          // `\` before a non-escape char is literal (both chars kept).
          current += ch;
          hasContent = true;
        }
        continue;
      }
      if (ch === '"') {
        inDouble = false;
      } else {
        current += ch;
        hasContent = true;
      }
      continue;
    }

    // Outside any quotes.
    if (ch === "'") {
      inSingle = true;
      hasContent = true; // an empty quote pair is a deliberate empty arg
      continue;
    }
    if (ch === '"') {
      inDouble = true;
      hasContent = true;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") {
      if (hasContent) {
        result.push(current);
        current = "";
        hasContent = false;
      }
      continue;
    }

    current += ch;
    hasContent = true;
  }

  if (hasContent) {
    result.push(current);
  }

  return result;
}

/**
 * True if an argument needs to be wrapped in quotes when formatted as a string.
 * An arg needs quoting if it contains whitespace (would split on re-parse) or
 * a quote character (would break parsing). An empty string also needs quoting
 * (otherwise it would disappear entirely).
 */
function needsQuoting(arg: string): boolean {
  if (arg.length === 0) return true;
  return /[\s"']/.test(arg);
}

/**
 * Format an array of arguments back into a single display string.
 *
 * Each arg that contains whitespace or quote characters is wrapped in double
 * quotes, with internal double quotes escaped as `\"`. This is the inverse of
 * {@link parseArgs}: `parseArgs(formatArgs(args))` always equals `args`.
 */
export function formatArgs(args: string[]): string {
  return args
    .map((arg) => {
      if (!needsQuoting(arg)) {
        return arg;
      }
      // Escape backslashes and double quotes, then wrap in double quotes.
      // Single quotes inside the arg are fine — they're literal inside double quotes.
      const escaped = arg.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
      return `"${escaped}"`;
    })
    .join(" ");
}
