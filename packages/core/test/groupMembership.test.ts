import { describe, expect, it } from "vitest";

import {
  createAccountKeyset,
  randomBytes,
  signGroupMembership,
  verifyGroupMembership,
} from "@keymember/core";
import type { GroupMembership } from "@keymember/core";

/**
 * ### signer
 *
 * A fresh account's signing key pair.
 *
 * @returns The key pair
 */
function signer() {
  return createAccountKeyset("admin", randomBytes(32), 1).keyset.signing;
}

const admin = signer();
const membership: GroupMembership = {
  groupId: "group",
  keysetVersion: 2,
  userId: "bob",
  wrappedPrivateKey: new Uint8Array([1, 2, 3]),
};

describe("group membership signatures", () => {
  it("verifies a membership the admin signed", () => {
    const signature = signGroupMembership(admin.privateKey, membership);

    expect(verifyGroupMembership(admin.publicKey, membership, signature)).toBe(
      true,
    );
  });

  it("rejects another member, version, wrap or signer", () => {
    const signature = signGroupMembership(admin.privateKey, membership);
    const other = signer();

    for (const changed of [
      { ...membership, userId: "mallory" },
      { ...membership, keysetVersion: 3 },
      { ...membership, groupId: "other" },
      { ...membership, wrappedPrivateKey: new Uint8Array([1, 2, 4]) },
    ]) {
      expect(verifyGroupMembership(admin.publicKey, changed, signature)).toBe(
        false,
      );
    }

    expect(verifyGroupMembership(other.publicKey, membership, signature)).toBe(
      false,
    );
  });
});
