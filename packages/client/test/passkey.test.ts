import {
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { decode } from "cborg";
import { describe, expect, it } from "vitest";

import { assertPasskey, createPasskey, rpIdAllowed } from "@keymember/client";
import { randomBytes, toBase64Url } from "@keymember/core";

const ORIGIN = "https://login.example.com";
const RP_ID = "example.com";

describe("rpIdAllowed", () => {
  it("accepts the host itself and its registrable-domain suffixes", () => {
    expect(rpIdAllowed("login.example.com", ORIGIN)).toBe(true);
    expect(rpIdAllowed("example.com", ORIGIN)).toBe(true);
    expect(rpIdAllowed("example.com", "https://app.example.com")).toBe(true);
    expect(rpIdAllowed("localhost", "http://localhost:3000")).toBe(true);
  });

  it("refuses other sites, public suffixes, IPs and insecure origins", () => {
    expect(rpIdAllowed("evil.com", ORIGIN)).toBe(false);
    expect(rpIdAllowed("com", ORIGIN)).toBe(false);
    expect(rpIdAllowed("co.kr", "https://app.example.com")).toBe(false);
    expect(rpIdAllowed("github.io", "https://alice.github.io")).toBe(false);
    expect(rpIdAllowed("ample.com", "https://example.com")).toBe(false);
    expect(rpIdAllowed("10.0.0.1", "https://10.0.0.1")).toBe(false);
    expect(rpIdAllowed("example.com", "http://example.com")).toBe(false);
  });
});

describe("passkey ceremonies, verified by an independent relying party library", () => {
  it("registers and then signs in", async () => {
    const registrationChallenge = randomBytes(32);
    const { passkey, credential } = createPasskey(
      {
        origin: ORIGIN,
        rpId: RP_ID,
        challenge: registrationChallenge,
        userVerified: true,
      },
      { id: randomBytes(16), name: "kim@example.com", displayName: "Kim" },
    );
    const registration = await verifyRegistrationResponse({
      response: {
        id: passkey.credentialId,
        rawId: toBase64Url(credential.rawId),
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: toBase64Url(credential.clientDataJSON),
          attestationObject: toBase64Url(credential.attestationObject),
          transports: ["internal"],
        },
      },
      expectedChallenge: toBase64Url(registrationChallenge),
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      requireUserVerification: true,
    });

    expect(registration.verified).toBe(true);
    expect(registration.registrationInfo?.credentialBackedUp).toBe(true);

    const info = registration.registrationInfo;

    if (info === undefined) {
      return;
    }

    const loginChallenge = randomBytes(32);
    const assertion = assertPasskey(passkey, {
      origin: ORIGIN,
      rpId: RP_ID,
      challenge: loginChallenge,
      userVerified: true,
    });
    const authentication = await verifyAuthenticationResponse({
      response: {
        id: passkey.credentialId,
        rawId: toBase64Url(assertion.rawId),
        type: "public-key",
        clientExtensionResults: {},
        response: {
          clientDataJSON: toBase64Url(assertion.clientDataJSON),
          authenticatorData: toBase64Url(assertion.authenticatorData),
          signature: toBase64Url(assertion.signature),
          userHandle: toBase64Url(assertion.userHandle),
        },
      },
      expectedChallenge: toBase64Url(loginChallenge),
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: {
        id: info.credential.id,
        publicKey: info.credential.publicKey,
        counter: info.credential.counter,
      },
      requireUserVerification: true,
    });

    expect(authentication.verified).toBe(true);
  });

  it("produces assertions a relying party rejects for another origin or challenge", async () => {
    const { passkey, credential } = createPasskey(
      {
        origin: ORIGIN,
        rpId: RP_ID,
        challenge: randomBytes(32),
        userVerified: true,
      },
      { id: randomBytes(16), name: "kim", displayName: "Kim" },
    );
    const challenge = randomBytes(32);
    const assertion = assertPasskey(passkey, {
      origin: ORIGIN,
      rpId: RP_ID,
      challenge,
      userVerified: true,
    });
    const response = {
      id: passkey.credentialId,
      rawId: toBase64Url(assertion.rawId),
      type: "public-key" as const,
      clientExtensionResults: {},
      response: {
        clientDataJSON: toBase64Url(assertion.clientDataJSON),
        authenticatorData: toBase64Url(assertion.authenticatorData),
        signature: toBase64Url(assertion.signature),
      },
    };
    const registered = {
      id: passkey.credentialId,
      publicKey: coseKeyFrom(credential.attestationObject),
      counter: 0,
    };

    await expect(
      verifyAuthenticationResponse({
        response,
        expectedChallenge: toBase64Url(randomBytes(32)),
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        credential: registered,
      }),
    ).rejects.toThrow();
    await expect(
      verifyAuthenticationResponse({
        response,
        expectedChallenge: toBase64Url(challenge),
        expectedOrigin: "https://evil.example",
        expectedRPID: RP_ID,
        credential: registered,
      }),
    ).rejects.toThrow();
  });

  it("never signs for a different relying party than the passkey's", () => {
    const { passkey } = createPasskey(
      {
        origin: ORIGIN,
        rpId: RP_ID,
        challenge: randomBytes(32),
        userVerified: true,
      },
      { id: randomBytes(16), name: "kim", displayName: "Kim" },
    );

    expect(() =>
      assertPasskey(passkey, {
        origin: "https://evil.example",
        rpId: "evil.example",
        challenge: randomBytes(32),
        userVerified: true,
      }),
    ).toThrow(/another relying party/);
  });
});

/**
 * ### coseKeyFrom
 *
 * Extracts the COSE public key from an attestation object, as a relying party would store it:
 * authData is rpIdHash (32) ‖ flags (1) ‖ counter (4) ‖ AAGUID (16) ‖ id length (2) ‖ id ‖ key.
 *
 * @param attestationObject CBOR attestation object
 * @returns The COSE key bytes
 */
function coseKeyFrom(attestationObject: Uint8Array): Uint8Array<ArrayBuffer> {
  const decoded = decode(attestationObject, { useMaps: true }) as Map<
    string,
    unknown
  >;
  const authData = decoded.get("authData");

  if (!(authData instanceof Uint8Array)) {
    throw new Error("attestationObject has no authData");
  }

  const idLength = ((authData[53] ?? 0) << 8) | (authData[54] ?? 0);

  return new Uint8Array(authData.slice(55 + idLength));
}
