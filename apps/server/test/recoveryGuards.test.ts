import { recoverAccount, Session } from "@keymember/client";
import type { Transport } from "@keymember/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  bootstrapTeam,
  joinTeam,
  loginAs,
  rewriting,
  serverFixture,
} from "./harness.js";
import type { TestServer } from "./harness.js";

const DAY = 24 * 60 * 60 * 1000;

/**
 * ### Team
 *
 * Owner and admin Alice, and member Bob with a shared vault.
 */
interface Team {
  readonly owner: Session;
  readonly alice: Session;
  readonly bob: Session;
  readonly vaultId: string;
}

/**
 * ### setUpTeam
 *
 * Creates the team and gives Bob a vault to lose and get back.
 *
 * @param server Test server
 * @returns The sessions and Bob's vault
 */
async function setUpTeam(server: TestServer): Promise<Team> {
  const owner = (await bootstrapTeam(server)).session;
  const alice = (await joinTeam(server, owner, "alice@example.com", "admin"))
    .session;
  const bob = (await joinTeam(server, owner, "bob@example.com")).session;
  const vaultId = await owner.createVault("인프라", "shared", [
    { userId: bob.user.id, permission: "view" },
  ]);

  return { owner, alice, bob, vaultId };
}

/**
 * ### asObject
 *
 * A request body as a plain object, for tampering with it.
 *
 * @param body Body the honest client sent
 * @returns Its fields
 */
function asObject(body: unknown): Record<string, unknown> {
  return typeof body === "object" && body !== null
    ? { ...(body as Record<string, unknown>) }
    : {};
}

describe("server-side recovery guards against a hostile admin client", () => {
  const fixture = serverFixture(setUpTeam);
  let server: TestServer;
  let team: Team;

  beforeEach(async () => {
    ({ server, fixture: team } = await fixture.restore());
  });

  afterEach(async () => {
    await server.close();
  });

  /**
   * ### readyToComplete
   *
   * Takes Bob through request, approval, re-enrolment and certification, so only completing
   * the recovery is left.
   *
   * @returns The recovery id
   */
  const readyToComplete = async (): Promise<string> => {
    const recoveryId = await team.alice.recovery().request(team.bob.user.id);

    server.clock.now = new Date(server.clock.now.getTime() + 8 * DAY);

    const { recoveryToken } = await team.owner.recovery().approve(recoveryId);
    const recovered = await recoverAccount(
      server.transport,
      recoveryToken,
      "bob-new-password",
    );
    const newBob = await loginAs(
      server,
      "bob@example.com",
      "bob-new-password",
      recovered.secretKey,
    );

    await team.alice.orgAdmin().certify(newBob.user.id, newBob.fingerprint);

    return recoveryId;
  };

  /**
   * ### aliceThrough
   *
   * Alice's session talking through a transport that tampers with what her client sends.
   *
   * @param transport Tampering transport
   * @returns Her session
   */
  const aliceThrough = (transport: Transport): Session => {
    const session = Session.fromSnapshot(transport, team.alice.toSnapshot());

    session.setRoots(server.roots);

    return session;
  };

  /**
   * ### tamperingWithCompletion
   *
   * A transport that rewrites the body of the completion request.
   *
   * @param change Rewrites the honest body
   * @returns The transport
   */
  const tamperingWithCompletion = (
    change: (body: Record<string, unknown>) => Record<string, unknown>,
  ): Transport =>
    rewriting(server.transport, {
      request: (path, body) =>
        path.endsWith("/complete") ? change(asObject(body)) : body,
    });

  it("refuses to restore a vault the member did not have", async () => {
    const recoveryId = await readyToComplete();
    const widening = aliceThrough(
      tamperingWithCompletion((body) => ({
        ...body,
        access: [
          ...(body.access as Array<unknown>),
          {
            vaultId: crypto.randomUUID(),
            wrappedKey: "AAAA",
            grantSignature: "A".repeat(86),
            keyGeneration: 1,
          },
        ],
      })),
    );

    await expect(
      widening.recovery().complete(recoveryId),
    ).rejects.toMatchObject({ status: 400, code: "bad_request" });
  });

  it("refuses to restore a vault at a stale key generation", async () => {
    const recoveryId = await readyToComplete();
    const stale = aliceThrough(
      tamperingWithCompletion((body) => ({
        ...body,
        access: (body.access as Array<Record<string, unknown>>).map(
          (entry) => ({ ...entry, keyGeneration: 7 }),
        ),
      })),
    );

    await expect(stale.recovery().complete(recoveryId)).rejects.toMatchObject({
      status: 400,
      code: "bad_request",
    });
  });

  it("refuses to add the member to a group they were not in", async () => {
    const recoveryId = await readyToComplete();
    const adding = aliceThrough(
      tamperingWithCompletion((body) => ({
        ...body,
        groups: [
          {
            groupId: crypto.randomUUID(),
            wrappedPrivateKey: "AAAA",
            keysetVersion: 1,
          },
        ],
      })),
    );

    await expect(adding.recovery().complete(recoveryId)).rejects.toMatchObject({
      status: 400,
      code: "bad_request",
    });
  });

  it("refuses an admin's request to recover their own account", async () => {
    await expect(
      team.alice.recovery().request(team.alice.user.id),
    ).rejects.toMatchObject({ status: 400, code: "bad_request" });
  });

  it("refuses a second open recovery for the same member", async () => {
    await team.alice.recovery().request(team.bob.user.id);

    await expect(
      team.alice.recovery().request(team.bob.user.id),
    ).rejects.toMatchObject({ status: 409, code: "conflict" });
  });

  it("refuses a request that names keys the member no longer has", async () => {
    const lying = aliceThrough(
      rewriting(server.transport, {
        request: (path, body) =>
          path === "/api/org/recoveries"
            ? { ...asObject(body), keysetVersion: 5 }
            : body,
      }),
    );

    await expect(
      lying.recovery().request(team.bob.user.id),
    ).rejects.toMatchObject({ status: 400, code: "bad_request" });
  });

  it("refuses approval while either admin has been a member under 7 days", async () => {
    const recoveryId = await team.alice.recovery().request(team.bob.user.id);

    await expect(
      team.owner.recovery().approve(recoveryId),
    ).rejects.toMatchObject({ status: 403, code: "forbidden" });
  });

  it("refuses a recovery token after it expires", async () => {
    const recoveryId = await team.alice.recovery().request(team.bob.user.id);

    server.clock.now = new Date(server.clock.now.getTime() + 8 * DAY);

    const { recoveryToken } = await team.owner.recovery().approve(recoveryId);

    server.clock.now = new Date(server.clock.now.getTime() + 4 * DAY);

    await expect(
      recoverAccount(server.transport, recoveryToken, "bob-new-password"),
    ).rejects.toMatchObject({ status: 403 });
  });

  it("refuses to complete a recovery the server points at someone else", async () => {
    const { alice, bob, owner } = team;
    const recoveryId = await alice.recovery().request(bob.user.id);

    server.clock.now = new Date(server.clock.now.getTime() + 8 * DAY);

    const { recoveryToken } = await owner.recovery().approve(recoveryId);
    const recovered = await recoverAccount(
      server.transport,
      recoveryToken,
      "bob-new-password",
    );
    const newBob = await loginAs(
      server,
      "bob@example.com",
      "bob-new-password",
      recovered.secretKey,
    );

    await alice.orgAdmin().certify(newBob.user.id, newBob.fingerprint);

    const redirecting = Session.fromSnapshot(
      rewriting(server.transport, {
        response: (path, body) =>
          path.endsWith("/vault-keys")
            ? { ...asObject(body), userId: owner.user.id }
            : body,
      }),
      alice.toSnapshot(),
    );

    redirecting.setRoots(server.roots);
    await expect(redirecting.recovery().complete(recoveryId)).rejects.toThrow(
      /someone else/,
    );
  });

  it("stops an admin from approving a recovery with an admin they certified days before", async () => {
    const { alice, bob, owner } = team;
    // Owner certified Alice moments ago, so Alice cannot approve the owner's request yet
    const recoveryId = await owner.recovery().request(bob.user.id);

    await expect(alice.recovery().approve(recoveryId)).rejects.toMatchObject({
      status: 403,
    });
    await owner.recovery().cancel(recoveryId);

    server.clock.now = new Date(server.clock.now.getTime() + 8 * DAY);

    const later = await owner.recovery().request(bob.user.id);
    const { recoveryToken } = await alice.recovery().approve(later);

    expect(recoveryToken.length).toBeGreaterThan(0);
  });

  it("cancels recoveries when the member is suspended, so they cannot come back through one", async () => {
    const { alice, bob, owner } = team;
    const recoveryId = await alice.recovery().request(bob.user.id);

    await owner.orgAdmin().suspendMember(bob.user.id);
    server.clock.now = new Date(server.clock.now.getTime() + 8 * DAY);
    await expect(owner.recovery().approve(recoveryId)).rejects.toMatchObject({
      status: 409,
    });
  });
});
