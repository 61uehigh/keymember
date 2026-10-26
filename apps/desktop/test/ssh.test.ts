import { execFile, execFileSync, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  fingerprintOf,
  generateEd25519,
  loadSshKey,
  publicKeyLine,
  SshKeyError,
} from "../src/main/ssh/keys.js";
import type { SshKey } from "../src/main/ssh/keys.js";
import { handleAgentMessage, SshAgent } from "../src/main/ssh/SshAgent.js";
import type { AgentBackend } from "../src/main/ssh/SshAgent.js";

const hasOpenSsh =
  spawnSync("ssh-keygen", ["-?"], { stdio: "ignore" }).error === undefined;

/**
 * ### run
 *
 * Runs a command without blocking the event loop.
 *
 * @param command Program
 * @param args Arguments
 * @param env Extra environment
 * @returns Trimmed standard output
 */
async function run(
  command: string,
  args: Array<string>,
  env: Record<string, string>,
): Promise<string> {
  const { stdout } = await promisify(execFile)(command, args, {
    env: { ...process.env, ...env },
    encoding: "utf8",
    timeout: 20_000,
  });

  return stdout.trim();
}

/**
 * ### keygen
 *
 * Runs ssh-keygen and returns its trimmed output.
 *
 * @param args Arguments
 * @param input Standard input (ssh-keygen -Y verify reads the signed message from it)
 * @returns Standard output
 */
function keygen(args: Array<string>, input = ""): string {
  return execFileSync("ssh-keygen", args, {
    encoding: "utf8",
    input,
    // ssh-keygen falls back to prompting on the terminal when the agent fails; fail fast instead
    timeout: 20_000,
  }).trim();
}

describe.skipIf(!hasOpenSsh)("SSH keys and agent against OpenSSH", () => {
  let dir: string;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "keymember-ssh-"));
  });

  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  /**
   * ### opensshKey
   *
   * Generates a key with ssh-keygen.
   *
   * @param name File name
   * @param args Type options
   * @returns Private key text and ssh-keygen's own public key line and fingerprint
   */
  async function opensshKey(
    name: string,
    args: Array<string>,
  ): Promise<{ text: string; publicLine: string; fingerprint: string }> {
    const path = join(dir, name);

    keygen([...args, "-N", "", "-C", `${name}@test`, "-f", path, "-q"]);

    return {
      text: await readFile(path, "utf8"),
      publicLine: (await readFile(`${path}.pub`, "utf8")).trim(),
      fingerprint: keygen(["-lf", `${path}.pub`]).split(" ")[1] ?? "",
    };
  }

  it.each([
    ["ed25519", ["-t", "ed25519"]],
    ["ecdsa256", ["-t", "ecdsa", "-b", "256"]],
    ["ecdsa384", ["-t", "ecdsa", "-b", "384"]],
    ["ecdsa521", ["-t", "ecdsa", "-b", "521"]],
    ["rsa", ["-t", "rsa", "-b", "2048"]],
    ["rsa-pem", ["-t", "rsa", "-b", "2048", "-m", "PEM"]],
    ["ecdsa-pkcs8", ["-t", "ecdsa", "-b", "256", "-m", "PKCS8"]],
  ])("reads a %s key exactly as OpenSSH does", async (name, args) => {
    const generated = await opensshKey(name, args);
    const key = loadSshKey(generated.text);

    expect(publicKeyLine(key, `${name}@test`)).toBe(generated.publicLine);
    expect(fingerprintOf(key.publicBlob)).toBe(generated.fingerprint);
  });

  it("generates Ed25519 keys that ssh-keygen accepts", async () => {
    const generated = generateEd25519("deploy@keymember");
    const path = join(dir, "generated");

    await writeFile(path, generated.privateKey, { mode: 0o600 });

    // Newer ssh-keygen also prints the comment; the key itself is the first two fields
    expect(keygen(["-y", "-f", path]).split(" ").slice(0, 2)).toEqual(
      generated.publicKey.split(" ").slice(0, 2),
    );
    expect(keygen(["-lf", path]).split(" ")[1]).toBe(generated.fingerprint);
  });

  it("refuses passphrase-protected keys with a clear message", async () => {
    const path = join(dir, "locked");

    keygen(["-t", "ed25519", "-N", "secret-pass", "-f", path, "-q"]);

    const text = await readFile(path, "utf8");

    expect(() => loadSshKey(text)).toThrow(SshKeyError);
    expect(() => loadSshKey(text)).toThrow(/passphrase/i);
  });

  it("serves ssh-add and signs for ssh-keygen through the agent socket", async () => {
    const keys: Array<{ key: SshKey; comment: string }> = [];

    for (const [name, args] of [
      ["agent-ed25519", ["-t", "ed25519"]],
      ["agent-ecdsa", ["-t", "ecdsa", "-b", "384"]],
      ["agent-rsa", ["-t", "rsa", "-b", "2048"]],
    ] as const) {
      keys.push({
        key: loadSshKey((await opensshKey(name, [...args])).text),
        comment: name,
      });
    }

    const asked: Array<string> = [];
    const backend: AgentBackend = {
      identities: () =>
        Promise.resolve(
          keys.map(({ key, comment }) => ({
            publicBlob: key.publicBlob,
            comment,
          })),
        ),
      sign: (blob, data, flags) => {
        const entry = keys.find(({ key }) =>
          Buffer.from(key.publicBlob).equals(Buffer.from(blob)),
        );

        asked.push(entry?.comment ?? "unknown");

        return Promise.resolve(entry?.key.sign(data, flags));
      },
    };
    const agent = new SshAgent(backend);
    const socket = join(dir, "agent.sock");

    await agent.listen(socket);

    try {
      const env = { SSH_AUTH_SOCK: socket };
      // The agent lives in this process, so its clients must not block the event loop
      const listed = (await run("ssh-add", ["-L"], env)).split("\n");

      expect(listed).toHaveLength(3);

      for (const [index, line] of listed.entries()) {
        const publicPath = join(dir, `signer-${String(index)}.pub`);
        const message = join(dir, `message-${String(index)}.txt`);

        await writeFile(publicPath, `${line}\n`);
        await writeFile(message, "deploy approval");
        // With only a public key given, ssh-keygen asks the agent to sign
        await run(
          "ssh-keygen",
          ["-Y", "sign", "-f", publicPath, "-n", "file", message],
          env,
        );
        await writeFile(
          join(dir, "allowed"),
          `signer ${line.split(" ").slice(0, 2).join(" ")}\n`,
        );

        expect(
          keygen(
            [
              "-Y",
              "verify",
              "-f",
              join(dir, "allowed"),
              "-I",
              "signer",
              "-n",
              "file",
              "-s",
              `${message}.sig`,
            ],
            "deploy approval",
          ),
        ).toContain("Good");
      }

      expect(asked).toEqual(["agent-ed25519", "agent-ecdsa", "agent-rsa"]);
    } finally {
      await agent.close();
    }
  });
});

describe("agent protocol edge cases", () => {
  const key = loadSshKey(generateEd25519("x").privateKey);
  const backend: AgentBackend = {
    identities: () =>
      Promise.resolve([{ publicBlob: key.publicBlob, comment: "x" }]),
    sign: () => Promise.resolve(undefined),
  };

  it("answers malformed, refused and unsupported requests with SSH_AGENT_FAILURE", async () => {
    const failure = Uint8Array.of(5);

    expect(await handleAgentMessage(new Uint8Array(), backend)).toEqual(
      failure,
    );
    expect(await handleAgentMessage(Uint8Array.of(13, 0, 0), backend)).toEqual(
      failure,
    );
    // Adding identities (17) belongs in the vault
    expect(await handleAgentMessage(Uint8Array.of(17), backend)).toEqual(
      failure,
    );

    const refused = Uint8Array.from([
      13,
      ...[0, 0, 0, key.publicBlob.length],
      ...key.publicBlob,
      0,
      0,
      0,
      1,
      42,
      0,
      0,
      0,
      0,
    ]);

    expect(await handleAgentMessage(refused, backend)).toEqual(failure);
  });

  it("refuses SHA-1 RSA signatures", async () => {
    if (!hasOpenSsh) {
      return;
    }

    const dir = await mkdtemp(join(tmpdir(), "keymember-rsa-"));

    try {
      keygen(["-t", "rsa", "-b", "2048", "-N", "", "-f", join(dir, "k"), "-q"]);

      const rsa = loadSshKey(await readFile(join(dir, "k"), "utf8"));

      expect(() => rsa.sign(Uint8Array.of(1), 0)).toThrow(SshKeyError);
      expect(rsa.sign(Uint8Array.of(1), 4).length).toBeGreaterThan(256);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
