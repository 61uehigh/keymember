import {
  inviteLinkUrl,
  parseInviteLink,
  Session,
  signUp,
} from "@keymember/client";
import type { InviteLink } from "@keymember/client";
import { createAccountKeyset, randomBytes } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  bootstrapTeam,
  joinTeam,
  loginAs,
  rewriting,
  startTestServer,
} from "./harness.js";
import type { Member, TestServer } from "./harness.js";

const SERVER_URL = "https://vault.example.test";
const DAY = 24 * 60 * 60 * 1000;

/**
 * ### jumpClientClock
 *
 * Moves the clock the SDK reads forward, as time passing on the admin's device.
 *
 * @param ms How far
 */
function jumpClientClock(ms: number): void {
  vi.setSystemTime(Date.now() + ms);
}

describe("invite links", () => {
  let server: TestServer;
  let owner: Member;

  afterEach(async () => {
    vi.useRealTimers();
    await server.close();
  });

  const start = async (): Promise<void> => {
    server = await startTestServer();
    owner = await bootstrapTeam(server);
  };

  /**
   * ### invite
   *
   * Has `admin` invite `email`, and reads the link back the way the join page does.
   *
   * @param admin Inviting admin
   * @param email Invitee
   * @returns The invite as the invitee receives it
   */
  /**
   * ### certified
   *
   * Runs the admin's automatic certification and keeps the emails it certified.
   *
   * @param admin Admin whose app runs it
   * @returns Emails certified now
   */
  const certified = async (admin: Session): Promise<ReadonlyArray<string>> =>
    (await admin.orgAdmin().certifyInvited()).certified;

  const invite = async (
    admin: Session,
    email: string,
    role: "admin" | "member" = "member",
  ): Promise<InviteLink & { serverUrl: string }> => {
    const { link } = await admin.orgAdmin().invite(email, role);
    const parsed = parseInviteLink(inviteLinkUrl(SERVER_URL, link));

    if (parsed === undefined) {
      throw new Error("The invite link did not parse");
    }

    return parsed;
  };

  /**
   * ### join
   *
   * Signs up from an invite and logs in.
   *
   * @param link Invite as received
   * @param withSecret Whether to prove the keys with the link's secret
   * @returns The new member's session and credentials
   */
  const join = async (
    link: InviteLink,
    withSecret = true,
  ): Promise<{ session: Session; password: string; secretKey: SecretKey }> => {
    const password = `${link.email}-password`;
    const account = await signUp(
      server.transport,
      link.token,
      { email: link.email, name: link.email, password },
      withSecret ? link.secret : undefined,
    );
    const session = await loginAs(
      server,
      link.email,
      password,
      account.secretKey,
    );

    return { session, password, secretKey: account.secretKey };
  };

  it("carries the token, email, secret and the admin's roots to the join page", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");

    expect(link.serverUrl).toBe(SERVER_URL);
    expect(link.email).toBe("bob@example.com");
    expect(link.secret).toHaveLength(32);
    expect([...link.roots]).toEqual([
      [owner.session.user.id, owner.session.signingPublicKey],
    ]);
  });

  it("certifies a member who joined by link, so they can be shared with, without a fingerprint", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");
    const bob = await join(link);

    bob.session.setRoots(link.roots);

    expect(await certified(owner.session)).toEqual(["bob@example.com"]);

    const vaultId = await owner.session.createVault("Infra", "shared", [
      { userId: bob.session.user.id, permission: "view" },
    ]);

    await bob.session.sync();
    expect(bob.session.listVaults().map((vault) => vault.id)).toEqual([
      vaultId,
    ]);

    // Nothing is left to certify
    expect(await certified(owner.session)).toEqual([]);
  });

  it("lets the member's other devices adopt the roots they saved", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");
    const bob = await join(link);

    expect(await bob.session.storedTrustedRoots()).toBeUndefined();

    bob.session.setRoots(link.roots);
    await bob.session.saveTrustedRoots();

    const laptop = await logInAgain(bob, link.email);

    expect([...((await laptop.storedTrustedRoots()) ?? [])]).toEqual([
      ...link.roots,
    ]);
  });

  it("ignores saved roots the server rewrote", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");
    const bob = await join(link);

    bob.session.setRoots(link.roots);
    await bob.session.saveTrustedRoots();

    const [row] = await server.tables.select("users", {
      id: bob.session.user.id,
    });
    const statement = row?.trusted_roots as {
      roots: Array<{ userId: string; signingPublicKey: string }>;
    };

    // A hostile server plants its own key as the organisation's root
    await server.tables.update(
      "users",
      { id: bob.session.user.id },
      {
        trusted_roots: {
          ...statement,
          roots: [
            {
              userId: owner.session.user.id,
              signingPublicKey: "A".repeat(43),
            },
          ],
        },
      },
    );

    expect(await bob.session.storedTrustedRoots()).toBeUndefined();
  });

  it("does not certify keys the server swapped after sign-up", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");
    const bob = await join(link);
    const attacker = createAccountKeyset(
      bob.session.user.id,
      randomBytes(32),
      1,
    ).stored;

    await server.tables.update(
      "users",
      { id: bob.session.user.id },
      {
        encryption_public_key: attacker.publicBundle.encryptionPublicKey,
        signing_public_key: attacker.publicBundle.signingPublicKey,
        self_signature: attacker.selfSignature,
      },
    );

    expect(await certified(owner.session)).toEqual([]);
    expect(
      (await owner.session.directory()).find(
        (member) => member.userId === bob.session.user.id,
      )?.certificate,
    ).toBeUndefined();
  });

  it("leaves a member who typed the token in for a fingerprint check", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");
    const bob = await join(link, false);

    expect(await certified(owner.session)).toEqual([]);

    await owner.session
      .orgAdmin()
      .certify(bob.session.user.id, bob.session.fingerprint);
    expect(
      (await owner.session.directory()).find(
        (member) => member.userId === bob.session.user.id,
      )?.certificate,
    ).toBeDefined();
  });

  it("leaves other admins' invites to the admin who sent them", async () => {
    await start();

    const alice = await joinTeam(
      server,
      owner.session,
      "alice@example.com",
      "admin",
    );

    alice.session.setRoots(server.roots);

    const link = await invite(alice.session, "bob@example.com");

    await join(link);

    expect(await certified(owner.session)).toEqual([]);
    expect(await certified(alice.session)).toEqual(["bob@example.com"]);
  });

  it("leaves admin invites to a fingerprint check, since an admin also gets the recovery key", async () => {
    await start();

    const link = await invite(owner.session, "alice@example.com", "admin");

    await join(link);

    const result = await owner.session.orgAdmin().certifyInvited();

    expect(result.certified).toEqual([]);
    expect(result.needsFingerprint).toEqual(["alice@example.com"]);
  });

  it("does not let an old link vouch for keys", async () => {
    await start();

    const link = await invite(owner.session, "bob@example.com");

    await join(link);
    // The link sat in someone's mail for weeks before the admin's app looked at it
    server.clock.now = new Date(server.clock.now.getTime() + 15 * DAY);
    vi.useFakeTimers({ toFake: ["Date"] });
    jumpClientClock(15 * DAY);

    const result = await owner.session.orgAdmin().certifyInvited();

    expect(result.certified).toEqual([]);
    expect(result.needsFingerprint).toEqual(["bob@example.com"]);
  });

  it("refuses an invite the server attached to a second account", async () => {
    await start();

    const first = await invite(owner.session, "bob@example.com");

    await join(first);

    const second = await invite(owner.session, "carol@example.com");

    await join(second);

    // A hostile server copies Bob's signed invite and proof row onto Carol's sign-up
    const [bobInvite] = await server.tables.select("invites", {
      email: "bob@example.com",
    });

    await server.tables.update(
      "invites",
      { email: "carol@example.com" },
      { statement: bobInvite?.statement },
    );

    const result = await owner.session.orgAdmin().certifyInvited();

    // One invite now backs two accounts, so the link vouches for neither
    expect(result.certified).toEqual([]);
    expect(result.needsFingerprint).toContain("bob@example.com");
  });

  /**
   * ### logInAgain
   *
   * Logs the same account in as another device would, with no roots pinned.
   *
   * @param member Account and its first session
   * @param email Account email
   * @returns The new device's session
   */
  const logInAgain = async (
    member: { password: string; secretKey: SecretKey },
    email: string,
  ): Promise<Session> => {
    const session = await loginAs(
      server,
      email,
      member.password,
      member.secretKey,
    );

    session.setRoots(new Map());

    return session;
  };

  it("certifies with the role the inviting admin signed, not the role the server reports", async () => {
    await start();

    const { inviteToken } = await owner.session
      .orgAdmin()
      .invite("dave@example.com", "member");
    const created = await signUp(server.transport, inviteToken, {
      email: "dave@example.com",
      name: "dave",
      password: "dave-password",
    });
    const dave = await loginAs(
      server,
      "dave@example.com",
      "dave-password",
      created.secretKey,
    );
    const promoting = Session.fromSnapshot(
      rewriting(server.transport, {
        response: (path, body) => {
          if (path !== "/api/org") {
            return body;
          }

          const org = body as { members: Array<Record<string, unknown>> };

          return {
            ...org,
            members: org.members.map((member) =>
              member.userId === dave.user.id
                ? { ...member, role: "admin" }
                : member,
            ),
          };
        },
      }),
      owner.session.toSnapshot(),
    );

    promoting.setRoots(server.roots);
    await promoting.orgAdmin().certify(dave.user.id, dave.fingerprint);

    const [row] = (await server.tables.select("memberships", {
      user_id: dave.user.id,
    })) as Array<{ certificate: { role: string } | null }>;
    const copies = await server.tables.select("recovery_key_access", {
      admin_id: dave.user.id,
    });

    expect(row?.certificate?.role).toBe("member");
    expect(copies).toEqual([]);
  });
});
