import {
  ApiError,
  bootstrapOrganization,
  logIn,
  send,
  Session,
} from "@keymember/client";
import type { Transport } from "@keymember/client";
import {
  DEFAULT_KDF_PARAMS,
  deriveAccountSecrets,
  deriveAuthVerifier,
  fromBase64Url,
  KdfParametersRejectedError,
} from "@keymember/core";
import type { KdfParams, SecretKey } from "@keymember/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { codeForStep } from "@keymember/server";

import { base32Decode, loginAs, startTestServer } from "./harness.js";
import type { TestServer } from "./harness.js";

const EMAIL = "owner@example.com";
const PASSWORD = "owner-password";

describe("authentication hardening", () => {
  let server: TestServer;
  let secretKey: SecretKey;

  beforeEach(async () => {
    server = await startTestServer();
    secretKey = (
      await bootstrapOrganization(server.transport, "Example", {
        email: EMAIL,
        name: "Owner",
        password: PASSWORD,
      })
    ).secretKey;
  });

  afterEach(async () => {
    await server.close();
  });

  it("answers prelogin for unknown emails with stable, realistic values", async () => {
    const prelogin = (email: string) =>
      send(server.transport, {
        method: "POST",
        path: "/api/auth/prelogin",
        body: { email },
      }) as Promise<{
        salt: string;
        kdf: unknown;
        method: string;
        challenge: string;
      }>;
    const known = await prelogin(EMAIL);
    const unknownFirst = await prelogin("nobody@example.com");
    const unknownAgain = await prelogin("nobody@example.com");

    expect(unknownFirst.salt).toBe(unknownAgain.salt);
    expect(unknownFirst.kdf).toEqual(known.kdf);
    expect(unknownFirst.method).toBe(known.method);
    expect(fromBase64Url(unknownFirst.challenge)?.length).toBe(32);
    expect(fromBase64Url(unknownFirst.salt)?.length).toBe(
      fromBase64Url(known.salt)?.length,
    );
  });

  it("gives the same error for a wrong password and an unknown email, then rate-limits", async () => {
    const wrongPassword = await loginAs(
      server,
      EMAIL,
      "wrong",
      secretKey,
    ).catch((error: unknown) => error);
    const unknownEmail = await loginAs(
      server,
      "nobody@example.com",
      "x",
      secretKey,
    ).catch((error: unknown) => error);

    expect(wrongPassword).toMatchObject({
      status: 401,
      code: "invalid_credentials",
    });
    expect(unknownEmail).toMatchObject({
      status: 401,
      code: "invalid_credentials",
    });

    for (let attempt = 0; attempt < 9; attempt += 1) {
      await loginAs(server, EMAIL, "wrong", secretKey).catch(() => undefined);
    }

    await expect(
      loginAs(server, EMAIL, PASSWORD, secretKey),
    ).rejects.toMatchObject({ status: 429 });

    server.clock.now = new Date(server.clock.now.getTime() + 16 * 60 * 1000);

    await expect(
      loginAs(server, EMAIL, PASSWORD, secretKey),
    ).resolves.toBeDefined();
  });

  it("refuses to derive keys when the server weakens the KDF", async () => {
    const downgrading: Transport = async (request) => {
      const response = await server.transport(request);

      if (request.path === "/api/auth/prelogin") {
        const body = response.body as Record<string, unknown>;

        return {
          status: 200,
          body: {
            ...body,
            kdf: {
              algorithm: "argon2id",
              memoryKiB: 8,
              iterations: 1,
              parallelism: 1,
            },
          },
        };
      }

      return response;
    };

    await expect(
      logIn(downgrading, {
        email: EMAIL,
        password: PASSWORD,
        secretKey,
        deviceId: crypto.randomUUID(),
        deviceName: "x",
      }),
    ).rejects.toBeInstanceOf(KdfParametersRejectedError);
  });

  it("rotates refresh tokens and revokes the whole login when an old one is replayed", async () => {
    const issued: Array<{ accessToken: string; refreshToken: string }> = [];
    const recording: Transport = async (request) => {
      const response = await server.transport(request);

      if (
        (request.path === "/api/auth/login" ||
          request.path === "/api/auth/refresh") &&
        response.status === 200
      ) {
        issued.push(
          response.body as { accessToken: string; refreshToken: string },
        );
      }

      return response;
    };

    await logIn(recording, {
      email: EMAIL,
      password: PASSWORD,
      secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "x",
    });

    const first = issued[0];

    if (first === undefined) {
      throw new Error("login issued no tokens");
    }

    const second = (await send(server.transport, {
      method: "POST",
      path: "/api/auth/refresh",
      body: { refreshToken: first.refreshToken },
    })) as { accessToken: string; refreshToken: string };

    // The rotated-away refresh token shows up again: treat it as stolen
    await expect(
      send(server.transport, {
        method: "POST",
        path: "/api/auth/refresh",
        body: { refreshToken: first.refreshToken },
      }),
    ).rejects.toMatchObject({ status: 401 });

    // Every token of that login, including the legitimately rotated one, is now dead
    await expect(
      send(server.transport, {
        method: "GET",
        path: "/api/org",
        token: second.accessToken,
      }),
    ).rejects.toMatchObject({ status: 401 });
    await expect(
      send(server.transport, {
        method: "POST",
        path: "/api/auth/refresh",
        body: { refreshToken: second.refreshToken },
      }),
    ).rejects.toMatchObject({ status: 401 });
  });

  it("enforces two-factor codes once enabled and rejects replayed codes", async () => {
    const session: Session = await loginAs(server, EMAIL, PASSWORD, secretKey);
    const { secret } = await session.setupTotp();
    const seed = base32Decode(secret);
    const step = () => Math.floor(server.clock.now.getTime() / 30_000);

    await session.confirmTotp(codeForStep(seed, step()));

    await expect(
      loginAs(server, EMAIL, PASSWORD, secretKey),
    ).rejects.toMatchObject({ code: "totp_required" });

    server.clock.now = new Date(server.clock.now.getTime() + 30_000);

    const code = codeForStep(seed, step());

    await expect(
      loginAs(server, EMAIL, PASSWORD, secretKey, code),
    ).resolves.toBeDefined();

    const replay = await loginAs(
      server,
      EMAIL,
      PASSWORD,
      secretKey,
      code,
    ).catch((error: unknown) => error);

    expect(replay).toBeInstanceOf(ApiError);
    expect(replay).toMatchObject({ code: "invalid_totp" });
  });

  it("restores a session from a snapshot and keeps the refreshed tokens", async () => {
    const original = await loginAs(server, EMAIL, PASSWORD, secretKey);

    await original.orgAdmin().initializeOrganization();

    original.setRoots(new Map([[original.user.id, original.signingPublicKey]]));

    const vaultId = await original.createVault("snap", "personal", []);
    let snapshot = original.toSnapshot();
    const restored = Session.fromSnapshot(
      server.transport,
      JSON.parse(JSON.stringify(snapshot)),
    );

    restored.onTokensChanged(() => {
      snapshot = restored.toSnapshot();
    });

    // Expire the access token so the next call must refresh
    server.clock.now = new Date(server.clock.now.getTime() + 20 * 60 * 1000);
    await restored.sync();

    expect(restored.listVaults().map((vault) => vault.id)).toEqual([vaultId]);
    expect(snapshot.tokens.refreshToken).not.toBe(
      original.toSnapshot().tokens.refreshToken,
    );
    expect(() =>
      Session.fromSnapshot(server.transport, { ...snapshot, v: 2 }),
    ).toThrow();
  });

  it("lets a user change their password and logs other devices out", async () => {
    const laptop = await loginAs(server, EMAIL, PASSWORD, secretKey);
    const phone = await loginAs(server, EMAIL, PASSWORD, secretKey);

    await laptop.changePassword(PASSWORD, "new-password");

    await expect(phone.sync()).rejects.toMatchObject({ status: 401 });
    await expect(
      loginAs(server, EMAIL, PASSWORD, secretKey),
    ).rejects.toMatchObject({ code: "invalid_credentials" });
    await expect(
      loginAs(server, EMAIL, "new-password", secretKey),
    ).resolves.toBeDefined();
  });
});

describe("signed-challenge login", () => {
  let server: TestServer;
  let secretKey: SecretKey;

  beforeEach(async () => {
    server = await startTestServer();
    secretKey = (
      await bootstrapOrganization(server.transport, "Example", {
        email: EMAIL,
        name: "Owner",
        password: PASSWORD,
      })
    ).secretKey;
  });

  afterEach(async () => {
    await server.close();
  });

  /**
   * ### recording
   *
   * Wraps the transport and keeps the bodies of login requests.
   *
   * @param bodies Where to keep them
   * @returns The recording transport
   */
  function recording(bodies: Array<Record<string, unknown>>): Transport {
    return async (request) => {
      if (request.path === "/api/auth/login") {
        bodies.push(request.body as Record<string, unknown>);
      }

      return server.transport(request);
    };
  }

  it("sends nothing that can be replayed to log in", async () => {
    const bodies: Array<Record<string, unknown>> = [];

    await logIn(recording(bodies), {
      email: EMAIL,
      password: PASSWORD,
      secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "x",
    });

    const [body] = bodies;

    expect(body).toHaveProperty("signature");
    expect(body).not.toHaveProperty("authKey");
    await expect(
      send(server.transport, {
        method: "POST",
        path: "/api/auth/login",
        body,
      }),
    ).rejects.toMatchObject({ status: 401 });
  });

  it("switches an account from the legacy verifier to signed login on its next login", async () => {
    const [row] = (await server.tables.select("users", {
      email: EMAIL,
    })) as Array<{
      salt: Uint8Array;
      kdf: KdfParams;
    }>;
    const secrets = await deriveAccountSecrets(
      PASSWORD,
      secretKey,
      row?.salt ?? new Uint8Array(),
      row?.kdf ?? DEFAULT_KDF_PARAMS,
    );

    // An account created before signed login only has the old verifier
    await server.tables.update(
      "users",
      { email: EMAIL },
      {
        auth_public_key: null,
        auth_verifier: deriveAuthVerifier(secrets.authenticationKey),
      },
    );

    const bodies: Array<Record<string, unknown>> = [];
    const input = {
      email: EMAIL,
      password: PASSWORD,
      secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "x",
    };

    await logIn(recording(bodies), input);
    await logIn(recording(bodies), input);

    expect(bodies[0]).toHaveProperty("authKey");
    expect(bodies[1]).toHaveProperty("signature");
    expect(bodies[1]).not.toHaveProperty("authKey");

    const [after] = await server.tables.select("users", { email: EMAIL });

    expect(after?.auth_verifier).toBeNull();

    // The old secret stops working once the account has a login key
    await expect(
      send(server.transport, {
        method: "POST",
        path: "/api/auth/login",
        body: bodies[0],
      }),
    ).rejects.toMatchObject({ status: 401 });
  });
});

describe("lockout resistance and first-run protection", () => {
  let server: TestServer;
  let secretKey: SecretKey;

  beforeEach(async () => {
    server = await startTestServer({ bootstrapToken: "first-run-token" });
  });

  afterEach(async () => {
    await server.close();
  });

  /**
   * ### bootstrap
   *
   * Creates the organisation with the right token.
   */
  async function bootstrap(): Promise<void> {
    secretKey = (
      await bootstrapOrganization(
        server.transport,
        "Example",
        { email: EMAIL, name: "Owner", password: PASSWORD },
        "first-run-token",
      )
    ).secretKey;
  }

  it("lets only the holder of the bootstrap token create the organisation", async () => {
    const account = { email: EMAIL, name: "Owner", password: PASSWORD };

    await expect(
      bootstrapOrganization(server.transport, "Example", account),
    ).rejects.toMatchObject({ status: 403, code: "bootstrap_token_invalid" });
    await expect(
      bootstrapOrganization(server.transport, "Example", account, "guess"),
    ).rejects.toMatchObject({ status: 403, code: "bootstrap_token_invalid" });

    await bootstrap();
  });

  it("keeps a known device signing in while strangers exhaust the per-email cap", async () => {
    await bootstrap();

    const deviceId = crypto.randomUUID();
    const signIn = (device: string) =>
      logIn(server.transport, {
        email: EMAIL,
        password: PASSWORD,
        secretKey,
        deviceId: device,
        deviceName: "vitest",
      });

    await signIn(deviceId);

    // Wrong guesses from many addresses: each stays under the per-address limit
    for (let attempt = 0; attempt < 50; attempt += 1) {
      await server.app.inject({
        method: "POST",
        url: "/api/auth/login",
        remoteAddress: `10.0.${String(Math.floor(attempt / 5))}.${String(attempt % 5)}`,
        payload: {
          email: EMAIL,
          authKey: "A".repeat(43),
          deviceId: crypto.randomUUID(),
          deviceName: "attacker",
        },
      });
    }

    await expect(signIn(crypto.randomUUID())).rejects.toMatchObject({
      status: 429,
    });
    await expect(signIn(deviceId)).resolves.toBeDefined();
  });

  it("ends a login that keeps guessing the current authenticator's code", async () => {
    await bootstrap();

    const session = await loginAs(server, EMAIL, PASSWORD, secretKey);
    const step = () => Math.floor(server.clock.now.getTime() / 30_000);
    const first = base32Decode((await session.setupTotp()).secret);

    await session.confirmTotp(codeForStep(first, step()));

    let ended = false;
    session.onEnded(() => {
      ended = true;
    });

    const second = base32Decode((await session.setupTotp()).secret);
    const wrong = codeForStep(first, step() + 100);

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await expect(
        session.confirmTotp(codeForStep(second, step()), wrong),
      ).rejects.toMatchObject({ code: "invalid_totp" });
    }

    await expect(session.sync()).rejects.toMatchObject({ status: 401 });
    expect(ended).toBe(true);
  });

  it("needs a code from the current authenticator to replace it", async () => {
    await bootstrap();

    const session = await loginAs(server, EMAIL, PASSWORD, secretKey);
    const step = Math.floor(server.clock.now.getTime() / 30_000);
    const first = base32Decode((await session.setupTotp()).secret);

    await session.confirmTotp(codeForStep(first, step));

    const second = base32Decode((await session.setupTotp()).secret);
    const next = codeForStep(second, step);

    await expect(session.confirmTotp(next)).rejects.toMatchObject({
      status: 403,
    });
    await session.confirmTotp(next, codeForStep(first, step + 1));
  });

  it("uses up the current authenticator's code when replacing it", async () => {
    await bootstrap();

    const session = await loginAs(server, EMAIL, PASSWORD, secretKey);
    const step = () => Math.floor(server.clock.now.getTime() / 30_000);
    const first = base32Decode((await session.setupTotp()).secret);

    await session.confirmTotp(codeForStep(first, step()));
    server.clock.now = new Date(server.clock.now.getTime() + 30_000);

    const current = codeForStep(first, step());
    const second = base32Decode((await session.setupTotp()).secret);

    // The code is claimed even though the new authenticator's code is wrong
    await expect(
      session.confirmTotp(codeForStep(second, step() + 100), current),
    ).rejects.toMatchObject({ code: "invalid_totp" });
    await expect(
      session.confirmTotp(codeForStep(second, step()), current),
    ).rejects.toMatchObject({ status: 403, code: "invalid_totp" });
  });
});
