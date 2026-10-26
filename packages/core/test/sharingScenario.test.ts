import { describe, expect, it } from "vitest";

import {
  createAccountKeyset,
  DecryptionError,
  decryptItemDetails,
  decryptItemOverview,
  encryptItem,
  generateEncryptionKeyPair,
  generateVaultKey,
  MalformedDataError,
  openItemKey,
  openVaultName,
  publicKeyFingerprint,
  randomBytes,
  sealAccountKeyset,
  sealVaultName,
  signMemberCertificate,
  unlockAccountKeyset,
  unwrapVaultKey,
  verifyMemberCertificate,
  wrapVaultKey,
} from "../src/index.js";
import type { AccountKeyset, MemberCertificate } from "../src/index.js";

import { sealItemKey } from "../src/item.js";

/**
 * ### certificateFor
 *
 * Builds the certificate an admin would sign when confirming a member.
 *
 * @param member Keyset of the member being certified
 * @param issuer Keyset of the confirming admin
 * @returns The unsigned certificate
 */
function certificateFor(
  member: AccountKeyset,
  issuer: AccountKeyset,
): MemberCertificate {
  return {
    orgId: "org-1",
    userId: member.userId,
    email: `${member.userId}@example.com`,
    encryptionPublicKey: member.encryption.publicKey,
    signingPublicKey: member.signing.publicKey,
    keysetVersion: member.keysetVersion,
    role: member.userId === issuer.userId ? "owner" : "member",
    issuerId: issuer.userId,
    issuedAt: 1_792_000_000,
  };
}

describe("AccountKeyset", () => {
  it("unlocks with the right AUK and keeps keys across a password change", () => {
    const oldAuk = randomBytes(32);
    const newAuk = randomBytes(32);
    const { keyset, stored } = createAccountKeyset("alice", oldAuk);
    const rewrapped = sealAccountKeyset(keyset, newAuk);

    expect(unlockAccountKeyset(stored, oldAuk)).toEqual(keyset);
    expect(unlockAccountKeyset(rewrapped, newAuk)).toEqual(keyset);
  });

  it("rejects a wrong AUK", () => {
    const { stored } = createAccountKeyset("alice", randomBytes(32));

    expect(() => unlockAccountKeyset(stored, randomBytes(32))).toThrow(
      DecryptionError,
    );
  });

  it("detects a server that substitutes the published encryption key", () => {
    const auk = randomBytes(32);
    const { stored } = createAccountKeyset("alice", auk);
    const substituted = {
      ...stored,
      publicBundle: {
        ...stored.publicBundle,
        encryptionPublicKey: generateEncryptionKeyPair().publicKey,
      },
    };

    expect(() => unlockAccountKeyset(substituted, auk)).toThrow(
      MalformedDataError,
    );
  });

  it("produces a stable, grouped fingerprint", () => {
    const { stored } = createAccountKeyset("alice", randomBytes(32));

    expect(publicKeyFingerprint(stored.publicBundle)).toMatch(
      /^[0-9a-f]{4}(-[0-9a-f]{4}){4}$/,
    );
    expect(publicKeyFingerprint(stored.publicBundle)).toBe(
      publicKeyFingerprint(stored.publicBundle),
    );
  });
});

describe("MemberCertificate", () => {
  const admin = createAccountKeyset("admin", randomBytes(32)).keyset;
  const bob = createAccountKeyset("bob", randomBytes(32)).keyset;
  const trusted = new Map([[admin.userId, admin.signing.publicKey]]);

  it("verifies a certificate signed by a trusted admin", () => {
    const certificate = certificateFor(bob, admin);

    expect(
      verifyMemberCertificate(
        certificate,
        signMemberCertificate(admin.signing.privateKey, certificate),
        trusted,
      ),
    ).toBe(true);
  });

  it("rejects a substituted public key, an altered email and an unknown issuer", () => {
    const certificate = certificateFor(bob, admin);
    const signature = signMemberCertificate(
      admin.signing.privateKey,
      certificate,
    );
    const mallory = createAccountKeyset("mallory", randomBytes(32)).keyset;

    expect(
      verifyMemberCertificate(
        { ...certificate, encryptionPublicKey: mallory.encryption.publicKey },
        signature,
        trusted,
      ),
    ).toBe(false);
    expect(
      verifyMemberCertificate(
        { ...certificate, email: "mallory@evil.test" },
        signature,
        trusted,
      ),
    ).toBe(false);
    expect(verifyMemberCertificate(certificate, signature, new Map())).toBe(
      false,
    );
  });
});

describe("sharing an item through a vault", () => {
  it("lets a certified member read what the owner stored, and nobody else", async () => {
    const alice = createAccountKeyset("alice", randomBytes(32)).keyset;
    const bob = createAccountKeyset("bob", randomBytes(32)).keyset;
    const eve = createAccountKeyset("eve", randomBytes(32)).keyset;

    // Alice, the admin, certifies Bob; Alice's client verifies the certificate before sharing
    const bobCertificate = certificateFor(bob, alice);
    const bobSignature = signMemberCertificate(
      alice.signing.privateKey,
      bobCertificate,
    );

    expect(
      verifyMemberCertificate(
        bobCertificate,
        bobSignature,
        new Map([["alice", alice.signing.publicKey]]),
      ),
    ).toBe(true);

    const vaultKey = generateVaultKey();
    const sealedName = sealVaultName(vaultKey, "vault-1", "인프라");
    const item = encryptItem(
      vaultKey,
      { vaultId: "vault-1", itemId: "item-1" },
      {
        type: "login",
        title: "AWS root",
        urls: ["https://console.aws.amazon.com"],
        tags: ["infra"],
      },
      {
        username: "root@example.com",
        password: "s3cret!",
        fields: [],
        passwordHistory: [],
      },
    );
    const forBob = await wrapVaultKey(vaultKey, "vault-1", 1, {
      principalId: bob.userId,
      encryptionPublicKey: bobCertificate.encryptionPublicKey,
    });

    const bobVaultKey = await unwrapVaultKey(
      forBob,
      "vault-1",
      1,
      bob.userId,
      bob.encryption,
    );
    const itemKey = openItemKey(bobVaultKey, item);

    expect(openVaultName(bobVaultKey, "vault-1", sealedName)).toBe("인프라");
    expect(decryptItemOverview(itemKey, item).title).toBe("AWS root");
    expect(decryptItemDetails(itemKey, item).password).toBe("s3cret!");

    // A server forwarding Bob's entry to Eve gets nothing out of it
    await expect(
      unwrapVaultKey(forBob, "vault-1", 1, eve.userId, eve.encryption),
    ).rejects.toThrow(DecryptionError);
  });

  it("moves an item between vaults by resealing only the item key", () => {
    const sourceKey = generateVaultKey();
    const targetKey = generateVaultKey();
    const item = encryptItem(
      sourceKey,
      { vaultId: "vault-a", itemId: "item-1" },
      { type: "secure-note", title: "Wi-Fi", urls: [], tags: [] },
      { notes: "guest / welcome", fields: [], passwordHistory: [] },
    );
    const itemKey = openItemKey(sourceKey, item);
    const moved = {
      ...item,
      vaultId: "vault-b",
      encryptedItemKey: sealItemKey(targetKey, "vault-b", "item-1", itemKey),
    };

    expect(decryptItemDetails(openItemKey(targetKey, moved), moved).notes).toBe(
      "guest / welcome",
    );

    // The old item key envelope cannot be relabelled as belonging to the new vault
    expect(() =>
      openItemKey(targetKey, { ...item, vaultId: "vault-b" }),
    ).toThrow(DecryptionError);
  });
});
