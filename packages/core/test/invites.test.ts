import { describe, expect, it } from "vitest";

import {
  createAccountKeyset,
  inviteLinkSecret,
  inviteProof,
  randomBytes,
  signTrustedRoots,
  verifyInviteProof,
  verifyTrustedRoots,
} from "@keymember/core";
import type { MemberInvite, TrustedRoots } from "@keymember/core";

const admin = account("admin");
const invitee = account("invitee");
/**
 * ### account
 *
 * A fresh account's private keys and published bundle.
 *
 * @param userId Account id
 * @returns Signing keys and public bundle
 */
function account(userId: string) {
  const { keyset, stored } = createAccountKeyset(userId, randomBytes(32), 1);

  return { signing: keyset.signing, publicBundle: stored.publicBundle };
}

const invite: MemberInvite = {
  orgId: "org",
  email: "bob@example.com",
  role: "member",
  issuerId: "admin",
  issuedAt: 1_800_000_000,
  nonce: "n1",
};

describe("invite links", () => {
  it("lets the admin check, from their key alone, that the invitee published these keys", () => {
    const secret = inviteLinkSecret(admin.signing.privateKey, invite);
    const proof = inviteProof(secret, invitee.publicBundle);

    // Another device of the same admin derives the same secret
    const again = inviteLinkSecret(admin.signing.privateKey, invite);

    expect(verifyInviteProof(again, invitee.publicBundle, proof)).toBe(true);
  });

  it("rejects keys a server swapped in after sign-up", () => {
    const secret = inviteLinkSecret(admin.signing.privateKey, invite);
    const proof = inviteProof(secret, invitee.publicBundle);
    const attacker = account("invitee");

    expect(verifyInviteProof(secret, attacker.publicBundle, proof)).toBe(false);
  });

  it("gives every invite, and every admin, a different secret", () => {
    const secret = inviteLinkSecret(admin.signing.privateKey, invite);
    const other = account("other");

    expect(
      inviteLinkSecret(admin.signing.privateKey, { ...invite, nonce: "n2" }),
    ).not.toEqual(secret);
    expect(inviteLinkSecret(other.signing.privateKey, invite)).not.toEqual(
      secret,
    );
  });

  it("refuses an invite without a nonce", () => {
    const { nonce: _nonce, ...legacy } = invite;

    expect(() => inviteLinkSecret(admin.signing.privateKey, legacy)).toThrow(
      /nonce/,
    );
  });
});

describe("trusted roots", () => {
  const roots: TrustedRoots = {
    userId: "invitee",
    orgId: "org",
    issuedAt: 1_800_000_000,
    roots: [
      {
        userId: "owner",
        signingPublicKey: admin.publicBundle.signingPublicKey,
      },
    ],
  };

  it("verifies roots the user signed, in any order", () => {
    const signature = signTrustedRoots(invitee.signing.privateKey, {
      ...roots,
      roots: [
        { userId: "z", signingPublicKey: new Uint8Array(32).fill(1) },
        ...roots.roots,
      ],
    });

    expect(
      verifyTrustedRoots(
        invitee.publicBundle.signingPublicKey,
        {
          ...roots,
          roots: [
            ...roots.roots,
            { userId: "z", signingPublicKey: new Uint8Array(32).fill(1) },
          ],
        },
        signature,
      ),
    ).toBe(true);
  });

  it("rejects roots the server changed or someone else signed", () => {
    const signature = signTrustedRoots(invitee.signing.privateKey, roots);
    const swapped: TrustedRoots = {
      ...roots,
      roots: [
        { userId: "owner", signingPublicKey: new Uint8Array(32).fill(9) },
      ],
    };

    expect(
      verifyTrustedRoots(
        invitee.publicBundle.signingPublicKey,
        swapped,
        signature,
      ),
    ).toBe(false);
    expect(
      verifyTrustedRoots(
        invitee.publicBundle.signingPublicKey,
        roots,
        signTrustedRoots(admin.signing.privateKey, roots),
      ),
    ).toBe(false);
  });
});
