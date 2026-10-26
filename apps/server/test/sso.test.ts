import { generateKeyPairSync } from "node:crypto";

import { ApiError, logIn, SsoRequiredError } from "@keymember/client";
import type { Session, SsoHandler } from "@keymember/client";
import type { SecretKey } from "@keymember/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { FakeIdp } from "./fakeIdp.js";
import type { IdpAccount } from "./fakeIdp.js";
import { bootstrapTeam, joinTeam, serverFixture } from "./harness.js";
import type { TestServer } from "./harness.js";

const DOMAIN = "example.com";

interface Member {
  session: Session;
  email: string;
  password: string;
  secretKey: SecretKey;
  google: IdpAccount;
}

describe("SSO login and offboarding", () => {
  let idp = new FakeIdp();
  let server: TestServer;
  let owner: Member;
  let bob: Member;
  let carol: Member;

  /**
   * ### browserAs
   *
   * An SSO handler that plays the browser: follows the start redirect, signs in at the fake
   * provider with the given account, and lands on the server's callback.
   *
   * @param account Provider account the user picks
   * @returns The handler
   */
  function browserAs(account: IdpAccount): SsoHandler {
    return {
      pollIntervalMs: 10,
      onChallenge: async ({ path }) => {
        // The first page only asks the user to confirm they started this login
        const confirmation = await server.app.inject({
          method: "GET",
          url: path,
        });

        expect(confirmation.body).toContain(
          "unless you just started this login yourself",
        );

        const start = await server.app.inject({
          method: "GET",
          url: `${path}&confirm=1`,
        });
        const { state, code } = idp.authorize(
          String(start.headers.location),
          account,
        );

        await server.app.inject({
          method: "GET",
          url: `/api/auth/sso/callback?${new URLSearchParams({ state, code }).toString()}`,
        });
      },
    };
  }

  /**
   * ### signIn
   *
   * Logs a member in on a new device, through the provider when a handler is given.
   *
   * @param member Member to log in
   * @param sso SSO handler
   * @returns The new session
   */
  async function signIn(member: Member, sso?: SsoHandler): Promise<Session> {
    return logIn(server.transport, {
      email: member.email,
      password: member.password,
      secretKey: member.secretKey,
      deviceId: crypto.randomUUID(),
      deviceName: "test",
      ...(sso === undefined ? {} : { sso }),
    });
  }

  /**
   * ### expireAccessTokens
   *
   * Moves the server clock past the access-token lifetime, so the next call refreshes.
   */
  function expireAccessTokens(): void {
    server.clock.now = new Date(server.clock.now.getTime() + 16 * 60 * 1000);
  }

  const fixture = serverFixture(
    async (server) => {
      const google = (email: string): IdpAccount => ({
        sub: `g-${email.split("@")[0] ?? email}`,
        email,
        hd: DOMAIN,
      });
      const owner = await bootstrapTeam(server, `owner@${DOMAIN}`);
      const join = async (name: string): Promise<Member> => {
        const member = await joinTeam(
          server,
          owner.session,
          `${name}@${DOMAIN}`,
        );

        return { ...member, google: google(member.email) };
      };

      return {
        owner: { ...owner, google: google(owner.email) },
        bob: await join("bob"),
        carol: await join("carol"),
      };
    },
    () => ({ sso: idp.config(DOMAIN), ssoFetch: idp.fetch }),
  );

  beforeEach(async () => {
    // A new provider per test; its keys are not part of the stored state
    idp = new FakeIdp();

    const restored = await fixture.restore();

    server = restored.server;
    ({ owner, bob, carol } = restored.fixture);
  });

  afterEach(async () => {
    await server.close();
  });

  /**
   * ### requireSso
   *
   * Links the owner's login to the provider and switches the policy on.
   */
  async function requireSso(): Promise<void> {
    await owner.session.linkSso(browserAs(owner.google));
    await owner.session.orgAdmin().setRequireSso(true);
  }

  it("only lets an admin require SSO after passing it themselves", async () => {
    await expect(
      owner.session.orgAdmin().setRequireSso(true),
    ).rejects.toMatchObject({
      status: 409,
      body: { error: "sso_not_linked" },
    });

    await requireSso();

    expect(await owner.session.policies()).toMatchObject({
      requireSso: true,
      ssoAvailable: true,
      ssoLinked: true,
    });
  });

  it("cuts off logins without SSO and admits members who pass it", async () => {
    await requireSso();

    // Bob's existing login never passed the provider
    await expect(bob.session.sync()).rejects.toMatchObject({
      body: { error: "sso_required" },
    });
    await expect(signIn(bob)).rejects.toBeInstanceOf(SsoRequiredError);

    const session = await signIn(bob, browserAs(bob.google));

    await session.sync();

    const [row] = await server.tables.select("users", {
      id: bob.session.user.id,
    });

    expect(row?.sso_subject).toBe("g-bob");
  });

  it("rejects the wrong provider account, another domain, a rebound email and a forged token", async () => {
    await requireSso();

    const failure = (account: IdpAccount) =>
      signIn(bob, browserAs(account)).then(
        () => "accepted",
        (error: unknown) =>
          error instanceof ApiError ? error.body : String(error),
      );

    expect(await failure(carol.google)).toMatchObject({ error: "sso_failed" });
    expect(await failure({ ...bob.google, hd: "other.example" })).toMatchObject(
      { error: "sso_failed" },
    );
    expect(
      await failure({ ...bob.google, emailVerified: false }),
    ).toMatchObject({ error: "sso_failed" });

    await signIn(bob, browserAs(bob.google));

    // The email now points at another provider account (e.g. reassigned after someone left)
    expect(
      await failure({ ...bob.google, sub: "g-someone-else" }),
    ).toMatchObject({ error: "sso_failed" });

    idp.signWith = generateKeyPairSync("rsa", {
      modulusLength: 2048,
    }).privateKey;
    expect(await failure(bob.google)).toMatchObject({ error: "sso_failed" });
  });

  it("does not hand the session to whoever only holds the ticket id", async () => {
    await requireSso();

    let ticketPath = "";

    const waiting = signIn(bob, {
      pollIntervalMs: 10,
      onChallenge: ({ path }) => {
        ticketPath = path;
        throw new Error("user closed the browser");
      },
    });

    await expect(waiting).rejects.toThrow("user closed the browser");

    const ticketId = new URLSearchParams(ticketPath.split("?")[1]).get(
      "ticket",
    );
    const stolen = await server.app.inject({
      method: "POST",
      url: "/api/auth/sso/finish",
      payload: { ticketId, ticketSecret: "guessed" },
    });

    expect(stolen.statusCode).toBe(404);
  });

  it("cancels an open recovery only when the SSO login succeeds", async () => {
    await requireSso();

    const recoveryId = await owner.session
      .recovery()
      .request(bob.session.user.id);
    const status = async () =>
      (await server.tables.select("recoveries", { id: recoveryId }))[0]?.status;

    // Between the provider callback and the finish, another account takes Bob's provider
    // identity, so the finish fails its last check
    const callback = browserAs(bob.google);
    const failing = signIn(bob, {
      ...callback,
      onChallenge: async (challenge) => {
        await callback.onChallenge(challenge);
        await server.tables.update(
          "users",
          { id: carol.session.user.id },
          { sso_subject: bob.google.sub },
        );
      },
    });

    await expect(failing).rejects.toMatchObject({
      body: { error: "sso_failed" },
    });
    expect(await status()).toBe("pending");

    await server.tables.update(
      "users",
      { id: carol.session.user.id },
      { sso_subject: null },
    );

    const session = await signIn(bob, browserAs(bob.google));

    expect(session.recoveryCancelled).toBe(true);
    expect(await status()).toBe("cancelled");
  });

  it("ends a login once the provider suspends the account, and tolerates a short outage", async () => {
    await requireSso();

    const session = await signIn(bob, browserAs(bob.google));

    // Provider down: refreshes keep working within the grace period
    idp.down = true;
    expireAccessTokens();
    await session.sync();

    // ...but not for longer than an hour since the last successful check
    server.clock.now = new Date(server.clock.now.getTime() + 61 * 60 * 1000);
    await expect(session.sync()).rejects.toMatchObject({
      status: 503,
      body: { error: "sso_unavailable" },
    });

    idp.down = false;
    await session.sync();

    idp.suspend("g-bob");
    expireAccessTokens();
    await expect(session.sync()).rejects.toMatchObject({
      status: 401,
      body: { error: "sso_revoked" },
    });

    const events = await owner.session.orgAdmin().auditLog();

    expect(events.map((event) => event.action)).toContain("auth.sso_revoked");
  });

  it("offboards a member: rotates their groups and the admin's vaults, and flags the rest", async () => {
    const admin = owner.session;
    const groupId = await admin
      .groupAdmin()
      .create("개발", [bob.session.user.id, carol.session.user.id]);
    const direct = await admin.createVault("인프라", "shared", [
      { userId: bob.session.user.id, permission: "view" },
    ]);
    const viaGroup = await admin.createVault(
      "배포",
      "shared",
      [],
      [{ groupId, permission: "view" }],
    );
    const carolsVault = await carol.session.createVault(
      "carol 관리",
      "shared",
      [{ userId: bob.session.user.id, permission: "edit" }],
    );

    await bob.session.createVault("bob 개인", "personal", []);

    const report = await admin.orgAdmin().offboard(bob.session.user.id);

    expect(report.groupsRotated).toEqual([groupId]);
    expect([...report.vaultsRotated].sort()).toEqual([direct, viaGroup].sort());
    expect(report.vaultsPending).toEqual([
      { vaultId: carolsVault, managerIds: [carol.session.user.id] },
    ]);
    expect(admin.listVaults().every((vault) => !vault.rotationDue)).toBe(true);

    await carol.session.sync();
    expect(
      carol.session.listVaults().find((vault) => vault.id === carolsVault)
        ?.rotationDue,
    ).toBe(true);

    await carol.session.rotateVaultKey(carolsVault);
    expect(
      carol.session.listVaults().find((vault) => vault.id === carolsVault)
        ?.rotationDue,
    ).toBe(false);

    const [group] = await admin.groups();

    expect(group?.keysetVersion).toBe(2);
    expect(group?.memberIds).toEqual([carol.session.user.id]);
  });
});
