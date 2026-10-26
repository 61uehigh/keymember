import { send } from "@keymember/client";
import type { Session } from "@keymember/client";
import { afterEach, describe, expect, it } from "vitest";

import { bootstrapTeam, joinTeam, startTestServer } from "./harness.js";
import type { TestServer } from "./harness.js";

/**
 * ### rawSync
 *
 * Calls sync as a client would, to read fields the SDK does not surface.
 *
 * @param server Test server
 * @param session Logged-in session whose token to use
 * @param since Revision the client has seen
 * @returns The sync response
 */
async function rawSync(
  server: TestServer,
  session: Session,
  since: number,
): Promise<{
  revision: number;
  reset: boolean;
  deletedItemIds: Array<string>;
}> {
  // The test reads only these fields of the server's sync response
  return (await send(server.transport, {
    method: "GET",
    path: `/api/sync?since=${String(since)}`,
    token: session.toSnapshot().tokens.accessToken,
  })) as { revision: number; reset: boolean; deletedItemIds: Array<string> };
}

describe("sync changes", () => {
  let server: TestServer;

  afterEach(async () => {
    await server.close();
  });

  it("tells a member to drop an item that moved to a vault they cannot open", async () => {
    server = await startTestServer();

    const owner = (await bootstrapTeam(server)).session;
    const bob = (await joinTeam(server, owner, "bob@example.com")).session;
    const shared = await owner.createVault("Shared", "shared", [
      { userId: bob.user.id, permission: "view" },
    ]);
    const privateVault = await owner.createVault("Private", "personal", []);
    const itemId = await owner.createItem(
      shared,
      { type: "login", title: "DB", urls: [], tags: [] },
      { password: "p", fields: [], passwordHistory: [] },
    );

    await bob.sync();
    expect(bob.listItems().map((item) => item.id)).toEqual([itemId]);

    const { revision } = await rawSync(server, bob, 0);

    await owner.sync();
    await owner.updateItem(
      itemId,
      { type: "login", title: "DB", urls: [], tags: [] },
      { password: "p", fields: [], passwordHistory: [] },
      privateVault,
    );

    expect((await rawSync(server, bob, revision)).deletedItemIds).toEqual([
      itemId,
    ]);

    await bob.sync();
    expect(bob.listItems()).toEqual([]);
  });

  it("sends everything again to a client ahead of the server, and says so", async () => {
    server = await startTestServer();

    const owner = (await bootstrapTeam(server)).session;
    const vaultId = await owner.createVault("Mine", "personal", []);

    await owner.createItem(
      vaultId,
      { type: "login", title: "A", urls: [], tags: [] },
      { password: "p", fields: [], passwordHistory: [] },
    );

    const current = await rawSync(server, owner, 0);
    const ahead = await rawSync(server, owner, current.revision + 1000);

    expect(current.reset).toBe(false);
    expect(ahead.reset).toBe(true);
    expect(ahead.revision).toBe(current.revision);
  });
});
