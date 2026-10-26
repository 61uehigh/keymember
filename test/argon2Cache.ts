import type * as Argon2 from "@noble/hashes/argon2.js";
import { vi } from "vitest";

// Argon2id at the production floor (64 MiB, 3 passes) dominates the suite: every sign-up and
// login derives it, and fixtures log the same accounts in again and again. Tests reuse the
// result for an identical (password, salt, parameters) call. Outputs are bit-identical, and
// the KDF floor check runs before Argon2id is reached, so no test sees weaker parameters.
vi.mock("@noble/hashes/argon2.js", async (importOriginal) => {
  const original = await importOriginal<typeof Argon2>();
  const cache = new Map<string, Promise<Uint8Array>>();
  const hex = (bytes: Uint8Array | string): string =>
    typeof bytes === "string"
      ? `s:${bytes}`
      : Buffer.from(bytes).toString("hex");

  return {
    ...original,
    argon2idAsync: (
      password: Parameters<typeof original.argon2idAsync>[0],
      salt: Parameters<typeof original.argon2idAsync>[1],
      options: Parameters<typeof original.argon2idAsync>[2],
    ): Promise<Uint8Array> => {
      const { onProgress: _ignored, ...rest } = options ?? {};
      const key = [
        hex(password),
        hex(salt),
        JSON.stringify(rest, (_, value: unknown) =>
          value instanceof Uint8Array ? hex(value) : value,
        ),
      ].join("|");
      let derived = cache.get(key);

      if (derived === undefined) {
        derived = original.argon2idAsync(password, salt, options);
        cache.set(key, derived);
        // A failed derivation is not worth remembering
        derived.catch(() => cache.delete(key));
      }

      // Callers may zero the result they get, so each gets its own copy
      return derived.then((bytes) => bytes.slice());
    },
  };
});
