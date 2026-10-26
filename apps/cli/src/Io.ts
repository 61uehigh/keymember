import { createInterface } from "node:readline";
import type { Interface } from "node:readline";

/**
 * ### Io
 *
 * Terminal interaction used by commands, injectable so tests can script answers.
 */
export interface Io {
  /**
   * ### print
   *
   * Writes a line to standard output.
   *
   * @param line Text to write
   */
  print(line: string): void;

  /**
   * ### warn
   *
   * Writes a line to standard error: something went wrong but the command's own result stands.
   *
   * @param line Text to write
   */
  warn(line: string): void;

  /**
   * ### ask
   *
   * Asks for a visible answer.
   *
   * @param question Prompt text
   * @returns The answer without the trailing newline
   */
  ask(question: string): Promise<string>;

  /**
   * ### askSecret
   *
   * Asks for a hidden answer such as a password; typed characters are not echoed.
   *
   * @param question Prompt text
   * @returns The answer
   */
  askSecret(question: string): Promise<string>;
}

/**
 * ### PipedLines
 *
 * Reads answers line by line from a non-interactive stdin. One reader serves every prompt,
 * because a reader per prompt would buffer and discard the lines meant for later prompts.
 */
class PipedLines {
  readonly #reader: Interface;
  readonly #buffered: Array<string> = [];
  readonly #waiting: Array<(line: string | undefined) => void> = [];
  #closed = false;

  /**
   * ### constructor
   *
   * Starts reading stdin.
   */
  constructor() {
    this.#reader = createInterface({ input: process.stdin, terminal: false });
    this.#reader.on("line", (line) => {
      const waiter = this.#waiting.shift();

      if (waiter === undefined) {
        this.#buffered.push(line);
      } else {
        waiter(line);
      }
    });
    this.#reader.on("close", () => {
      this.#closed = true;

      for (const waiter of this.#waiting.splice(0)) {
        waiter(undefined);
      }
    });
  }

  /**
   * ### next
   *
   * Returns the next line, failing when stdin ends first.
   *
   * @returns The next input line
   */
  async next(): Promise<string> {
    const buffered = this.#buffered.shift();

    if (buffered !== undefined) {
      return buffered;
    }

    if (this.#closed) {
      throw new Error("Input ended before every prompt was answered");
    }

    const line = await new Promise<string | undefined>((resolve) => {
      this.#waiting.push(resolve);
    });

    if (line === undefined) {
      throw new Error("Input ended before every prompt was answered");
    }

    return line;
  }

  /**
   * ### close
   *
   * Stops reading so the process can exit.
   */
  close(): void {
    this.#reader.close();
  }
}

/**
 * ### readHiddenLine
 *
 * Reads one line from an interactive terminal in raw mode without echoing it.
 * Supports backspace; Ctrl-C aborts the process.
 *
 * @returns The typed line
 */
function readHiddenLine(): Promise<string> {
  const stdin = process.stdin;

  return new Promise((resolve) => {
    let value = "";

    const onData = (chunk: Buffer): void => {
      for (const char of chunk.toString("utf8")) {
        if (char === "\r" || char === "\n") {
          stdin.off("data", onData);
          stdin.setRawMode(false);
          stdin.pause();
          process.stderr.write("\n");
          resolve(value);

          return;
        }

        if (char === "\u0003") {
          stdin.setRawMode(false);
          process.stderr.write("\n");
          process.exit(130);
        }

        value =
          char === "\u007f" || char === "\b"
            ? value.slice(0, -1)
            : value + char;
      }
    };

    stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

/**
 * ### terminalIo
 *
 * {@link Io} on the process's terminal. Prompts go to stderr so stdout stays clean for
 * piping values such as `keymember item get … --field password | pbcopy`. When stdin is
 * not a terminal, answers are read one per line from it, which lets scripts pipe them in.
 *
 * @returns Terminal-backed Io
 */
export function terminalIo(): Io {
  const interactive = process.stdin.isTTY;
  let piped: PipedLines | undefined;

  const pipedLine = async (question: string): Promise<string> => {
    piped ??= new PipedLines();
    process.stderr.write(question);

    const line = await piped.next();

    process.stderr.write("\n");

    return line;
  };

  // Release stdin once the command finishes so a piped run can exit
  process.once("beforeExit", () => {
    piped?.close();
  });

  return {
    print: (line) => {
      process.stdout.write(`${line}\n`);
    },
    warn: (line) => {
      process.stderr.write(`warning: ${line}\n`);
    },
    ask: async (question) => {
      if (!interactive) {
        return pipedLine(question);
      }

      const reader = createInterface({
        input: process.stdin,
        output: process.stderr,
      });

      try {
        return await new Promise<string>((resolve) => {
          reader.question(question, resolve);
        });
      } finally {
        reader.close();
      }
    },
    askSecret: async (question) => {
      if (!interactive) {
        return pipedLine(question);
      }

      process.stderr.write(question);

      return readHiddenLine();
    },
  };
}
