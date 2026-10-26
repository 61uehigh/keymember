import { chmod, rm } from "node:fs/promises";
import { createServer } from "node:net";
import type { Server, Socket } from "node:net";

import { SshReader, SshWriter } from "./wire.js";

// Message numbers from draft-miller-ssh-agent §6.1
const FAILURE = 5;
const REQUEST_IDENTITIES = 11;
const IDENTITIES_ANSWER = 12;
const SIGN_REQUEST = 13;
const SIGN_RESPONSE = 14;

// No legitimate request comes near this; anything larger is refused before buffering more
const MAX_MESSAGE_BYTES = 256 * 1024;

/**
 * ### AgentIdentity
 *
 * A key the agent offers.
 */
export interface AgentIdentity {
  /**
   * ### publicBlob
   *
   * Public key in SSH wire form.
   */
  readonly publicBlob: Uint8Array;

  /**
   * ### comment
   *
   * Name shown by `ssh-add -l`, normally the item title.
   */
  readonly comment: string;
}

/**
 * ### AgentBackend
 *
 * Where the agent gets keys and permission from: the unlocked vault and the user.
 */
export interface AgentBackend {
  /**
   * ### identities
   *
   * Keys to offer; empty while the vault is locked.
   */
  identities(): Promise<ReadonlyArray<AgentIdentity>>;

  /**
   * ### sign
   *
   * Signs with the key whose public blob matches, after the user allowed it. Resolves to
   * `undefined` when the key is unknown, the vault is locked, or the user refused.
   *
   * @param publicBlob Key to sign with
   * @param data Data from the SSH client
   * @param flags Request flags
   */
  sign(
    publicBlob: Uint8Array,
    data: Uint8Array,
    flags: number,
  ): Promise<Uint8Array | undefined>;
}

/**
 * ### handleAgentMessage
 *
 * Answers one agent request (without its length prefix). Only listing keys and signing are
 * supported; adding, removing and locking keys belong in the vault, so those get a failure.
 *
 * @param message Request body: type byte and contents
 * @param backend Keys and permission
 * @returns Response body
 */
export async function handleAgentMessage(
  message: Uint8Array,
  backend: AgentBackend,
): Promise<Uint8Array> {
  const failure = Uint8Array.of(FAILURE);

  try {
    const reader = new SshReader(message);
    const type = reader.byte();

    if (type === REQUEST_IDENTITIES) {
      const identities = await backend.identities();
      const writer = new SshWriter()
        .byte(IDENTITIES_ANSWER)
        .uint32(identities.length);

      for (const identity of identities) {
        writer.string(identity.publicBlob).string(identity.comment);
      }

      return writer.bytes();
    }

    if (type === SIGN_REQUEST) {
      const publicBlob = reader.string();
      const data = reader.string();
      const flags = reader.uint32();
      const signature = await backend.sign(publicBlob, data, flags);

      return signature === undefined
        ? failure
        : new SshWriter().byte(SIGN_RESPONSE).string(signature).bytes();
    }

    return failure;
  } catch {
    // A malformed request or a key that cannot sign this way gets the protocol's failure answer
    return failure;
  }
}

/**
 * ### SshAgent
 *
 * An OpenSSH agent on a Unix socket (`SSH_AUTH_SOCK`). The socket file is readable only by
 * the user; requests on one connection are answered in order.
 */
export class SshAgent {
  readonly #backend: AgentBackend;
  #server: Server | undefined;

  /**
   * ### constructor
   *
   * @param backend Keys and permission
   */
  constructor(backend: AgentBackend) {
    this.#backend = backend;
  }

  /**
   * ### listen
   *
   * Starts serving on a socket path, replacing a stale socket file left by a previous run.
   *
   * @param socketPath Path for `SSH_AUTH_SOCK`
   */
  async listen(socketPath: string): Promise<void> {
    await rm(socketPath, { force: true });

    const server = createServer((socket) => {
      this.#serve(socket);
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => {
        server.off("error", reject);
        resolve();
      });
    });
    // Other local users must not be able to ask for signatures
    await chmod(socketPath, 0o600);
    this.#server = server;
  }

  /**
   * ### close
   *
   * Stops serving.
   */
  async close(): Promise<void> {
    const server = this.#server;

    this.#server = undefined;

    if (server !== undefined) {
      await new Promise<void>((resolve) => {
        server.close(() => {
          resolve();
        });
      });
    }
  }

  /**
   * ### #serve
   *
   * Reads length-prefixed requests from a connection and writes the answers.
   *
   * @param socket Client connection
   */
  #serve(socket: Socket): void {
    let buffered = Buffer.alloc(0);
    let queue = Promise.resolve();

    socket.on("data", (chunk: Buffer) => {
      buffered = Buffer.concat([buffered, chunk]);

      while (buffered.length >= 4) {
        const length = buffered.readUInt32BE(0);

        if (length > MAX_MESSAGE_BYTES) {
          socket.destroy();

          return;
        }

        if (buffered.length < 4 + length) {
          return;
        }

        const message = new Uint8Array(buffered.subarray(4, 4 + length));

        buffered = buffered.subarray(4 + length);
        queue = queue.then(async () => {
          const response = await handleAgentMessage(message, this.#backend);

          if (!socket.destroyed) {
            socket.write(new SshWriter().string(response).bytes());
          }
        });
      }
    });
    socket.on("error", () => {
      // The client went away; nothing to answer
    });
  }
}
