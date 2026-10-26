import { describe, expect, it } from "vitest";

import {
  createAccountKeyset,
  randomBytes,
  signMemberCertificate,
  verifyDirectory,
} from "@keymember/core";
import type {
  AccountKeyset,
  DirectoryEntry,
  MemberRole,
} from "@keymember/core";

/**
 * ### certify
 *
 * Produces the directory entry an issuer would create for a member.
 *
 * @param member Keyset of the certified member
 * @param issuer Keyset of the signing admin
 * @param role Role written into the certificate
 * @returns The signed directory entry
 */
function certify(
  member: AccountKeyset,
  issuer: AccountKeyset,
  role: MemberRole,
): DirectoryEntry {
  const certificate = {
    orgId: "org-1",
    userId: member.userId,
    email: `${member.userId}@example.com`,
    encryptionPublicKey: member.encryption.publicKey,
    signingPublicKey: member.signing.publicKey,
    keysetVersion: member.keysetVersion,
    role,
    issuerId: issuer.userId,
    issuedAt: 1_792_000_000,
  };

  return {
    certificate,
    signature: signMemberCertificate(issuer.signing.privateKey, certificate),
  };
}

const keyset = (userId: string): AccountKeyset =>
  createAccountKeyset(userId, randomBytes(32)).keyset;

describe("verifyDirectory", () => {
  const owner = keyset("owner");
  const admin = keyset("admin");
  const member = keyset("member");
  const roots = new Map([[owner.userId, owner.signing.publicKey]]);

  it("follows owner → admin → member regardless of directory order", () => {
    const verified = verifyDirectory(
      [
        certify(member, admin, "member"),
        certify(admin, owner, "admin"),
        certify(owner, owner, "owner"),
      ],
      roots,
      "org-1",
    );

    expect([...verified.keys()].sort()).toEqual(["admin", "member", "owner"]);
  });

  it("does not let a plain member vouch for anyone", () => {
    const outsider = keyset("outsider");
    const verified = verifyDirectory(
      [
        certify(owner, owner, "owner"),
        certify(member, owner, "member"),
        certify(outsider, member, "member"),
      ],
      roots,
      "org-1",
    );

    expect(verified.has("outsider")).toBe(false);
  });

  it("ignores a certificate the server re-labels with a higher role", () => {
    const entry = certify(member, owner, "member");
    const promoted = {
      certificate:
        entry.certificate === undefined
          ? undefined
          : { ...entry.certificate, role: "admin" as const },
      signature: entry.signature,
    };

    expect(
      verifyDirectory(
        [certify(owner, owner, "owner"), promoted],
        roots,
        "org-1",
      ).has("member"),
    ).toBe(false);
  });

  it("rejects a root whose certificate carries a key other than the pinned one", () => {
    const impostor = keyset("owner");

    expect(
      verifyDirectory([certify(impostor, impostor, "owner")], roots, "org-1")
        .size,
    ).toBe(0);
  });

  it("ignores a certificate moved onto another member's row", () => {
    const moved = {
      ...certify(member, owner, "member"),
      userId: "someone-else",
    };

    expect(
      verifyDirectory([certify(owner, owner, "owner"), moved], roots, "org-1")
        .size,
    ).toBe(1);
  });

  it("verifies nobody listed on two rows, so an old certificate cannot be put first", () => {
    const replaced = keyset("member");

    expect(
      verifyDirectory(
        [
          certify(owner, owner, "owner"),
          { ...certify(replaced, owner, "member"), userId: "member" },
          { ...certify(member, owner, "member"), userId: "member" },
        ],
        roots,
        "org-1",
      ).has("member"),
    ).toBe(false);
  });
});
