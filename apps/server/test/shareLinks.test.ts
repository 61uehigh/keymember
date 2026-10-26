import {
  ApiError,
  openShareLink,
  parseShareLink,
  shareLinkUrl,
} from "@keymember/client";
import type { Session, ShareLink } from "@keymember/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { bootstrapTeam, joinTeam, serverFixture } from "./harness.js";
import type { TestServer } from "./harness.js";

const HOUR = 60 * 60 * 1000;

describe("share links", () => {
  const fixture = serverFixture(async (server) => {
    const owner = (await bootstrapTeam(server)).session;
    const bob = (await joinTeam(server, owner, "bob@example.com")).session;
    const vaultId = await owner.createVault("인프라", "shared", [
      { userId: bob.user.id, permission: "view" },
    ]);
    const itemId = await owner.createItem(
      vaultId,
      {
        type: "login",
        title: "외주 스테이징",
        urls: ["https://staging.example.com"],
        tags: [],
      },
      {
        username: "vendor",
        password: "staging-pass-42",
        notes: "internal note",
        fields: [],
        passwordHistory: [],
      },
    );

    return { owner, bob, itemId };
  });
  let server: TestServer;
  let owner: Session;
  let bob: Session;
  let itemId: string;

  beforeEach(async () => {
    const restored = await fixture.restore();

    server = restored.server;
    ({ owner, bob, itemId } = restored.fixture);
  });

  afterEach(async () => {
    await server.close();
  });

  /**
   * ### share
   *
   * Makes a link to the test item as the owner.
   *
   * @param options Link options to override
   * @returns The link
   */
  function share(
    options: Partial<Parameters<Session["createShareLink"]>[1]> = {},
  ): Promise<ShareLink> {
    return owner.createShareLink(itemId, {
      fields: ["username", "password"],
      expiresInMs: 24 * HOUR,
      maxViews: 2,
      ...options,
    });
  }

  it("opens without an account, shows only the chosen fields, and keeps the server blind", async () => {
    const link = await share();
    const url = shareLinkUrl("https://keymember.example.com", link);

    // Everything secret sits behind the fragment, which browsers never send
    expect(url.split("#")[0]).toBe("https://keymember.example.com/");
    expect(parseShareLink(url)).toEqual(link);

    const opened = await openShareLink(server.transport, link);

    expect(opened.snapshot).toEqual({
      title: "외주 스테이징",
      urls: ["https://staging.example.com"],
      username: "vendor",
      password: "staging-pass-42",
      sharedBy: "Owner",
    });
    expect(opened.viewsLeft).toBe(1);

    const rows = await server.tables.select("shares");

    expect(
      Buffer.from(
        (rows[0]?.ciphertext as Uint8Array | undefined) ?? [],
      ).toString("latin1"),
    ).not.toContain("staging-pass-42");
  });

  it("stops after the last view and after it expires", async () => {
    const link = await share({ maxViews: 1 });

    await openShareLink(server.transport, link);
    await expect(openShareLink(server.transport, link)).rejects.toMatchObject({
      status: 410,
    });

    const expiring = await share();

    server.clock.now = new Date(server.clock.now.getTime() + 25 * HOUR);
    await expect(
      openShareLink(server.transport, expiring),
    ).rejects.toMatchObject({ status: 410 });

    const [row] = await server.tables.select("shares", { id: link.shareId });

    expect(row?.ciphertext).toBeNull();
  });

  it("needs the passphrase, counts no view for a wrong one, and closes after ten", async () => {
    const link = await share({ passphrase: "보라색 우산" });

    expect(link.needsPassphrase).toBe(true);
    await expect(openShareLink(server.transport, link)).rejects.toMatchObject({
      status: 403,
      body: { error: "share_denied", attemptsLeft: 9 },
    });

    const opened = await openShareLink(server.transport, link, "보라색 우산");

    expect(opened.viewsLeft).toBe(1);

    const guessed = await share({ passphrase: "right", maxViews: 5 });

    for (let attempt = 0; attempt < 10; attempt += 1) {
      await openShareLink(
        server.transport,
        guessed,
        `wrong-${String(attempt)}`,
      ).catch((error: unknown) => error);
    }

    await expect(
      openShareLink(server.transport, guessed, "right"),
    ).rejects.toMatchObject({ status: 410 });
  });

  it("rejects a link whose secret was tampered with, without spending a view", async () => {
    const link = await share({ maxViews: 1 });
    const forged = {
      ...link,
      secret: link.secret.replace(/^./, (c) => (c === "A" ? "B" : "A")),
    };

    await expect(openShareLink(server.transport, forged)).rejects.toMatchObject(
      {
        status: 403,
      },
    );
    expect((await openShareLink(server.transport, link)).viewsLeft).toBe(0);
  });

  it("lets the sender and admins list and revoke links, and closes a leaver's links", async () => {
    const own = await share();
    const bobsLink = await bob.sync().then(() =>
      bob.createShareLink(itemId, {
        fields: ["password"],
        expiresInMs: HOUR,
        maxViews: 1,
      }),
    );

    expect((await bob.shareLinks()).map((entry) => entry.id)).toEqual([
      bobsLink.shareId,
    ]);
    await expect(bob.shareLinks({ all: true })).rejects.toMatchObject({
      status: 403,
    });
    expect(
      (await owner.shareLinks({ all: true })).map((entry) => entry.id).sort(),
    ).toEqual([own.shareId, bobsLink.shareId].sort());

    await owner.revokeShareLink(own.shareId);
    await expect(openShareLink(server.transport, own)).rejects.toMatchObject({
      status: 410,
    });
    await expect(bob.revokeShareLink(own.shareId)).rejects.toMatchObject({
      status: 404,
    });

    await owner.orgAdmin().suspendMember(bob.user.id);
    await expect(
      openShareLink(server.transport, bobsLink),
    ).rejects.toMatchObject({
      status: 410,
    });

    const actions = (await owner.orgAdmin().auditLog()).map(
      (event) => event.action,
    );

    expect(actions).toEqual(
      expect.arrayContaining(["share.created", "share.revoked"]),
    );
  });

  it("refuses links outside the allowed lifetime and to items the caller cannot read", async () => {
    await expect(share({ expiresInMs: 60 * 1000 })).rejects.toBeInstanceOf(
      ApiError,
    );
    await expect(share({ expiresInMs: 31 * 24 * HOUR })).rejects.toMatchObject({
      status: 400,
    });

    const privateVault = await owner.createVault("개인", "personal", []);
    const privateItem = await owner.createItem(
      privateVault,
      { type: "login", title: "p", urls: [], tags: [] },
      { password: "p", fields: [], passwordHistory: [] },
    );

    // Bob's client cannot even read the item; the server must refuse a hand-made request too
    const forged = await server.app.inject({
      method: "POST",
      url: "/api/shares",
      headers: {
        authorization: `Bearer ${bob.toSnapshot().tokens.accessToken}`,
      },
      payload: {
        id: crypto.randomUUID(),
        vaultId: privateVault,
        itemId: privateItem,
        ciphertext: "AAAA",
        accessHash: Buffer.alloc(32).toString("base64url"),
        passphrase: false,
        lifetimeSeconds: 3600,
        maxViews: 1,
      },
    });

    expect(forged.statusCode).toBe(404);
  });
});
