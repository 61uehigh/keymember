# Post-quantum migration path

keymember does not use post-quantum cryptography yet. This document sets out what changes, and in what order, once migration becomes necessary. The formats already allow for it.

## What is at risk

| Component | Algorithm | Against a quantum computer |
|---|---|---|
| Item and name encryption (envelope) | XChaCha20-Poly1305, 256-bit keys | Safe. Even with Grover, 128-bit security remains |
| Account key derivation | Argon2id + HKDF + Secret Key (128 bits) | Safe |
| Key wrapping (vault keys, group keys, recovery key) | HPKE X25519 | **At risk.** A DB copied today (harvest now) could have its vault keys unwrapped later |
| Signatures (certificates, grants, login) | Ed25519 | Could be forged later, but do not reveal past data. Less urgent to migrate than wrapping |

So **key wrapping** changes first.

## Already in place

- Wrapped keys are `{suite, enc, ct}` CBOR, and `unwrapKey` rejects an unknown `suite` with `MalformedDataError`. `suite = 1` is the current X25519 + HKDF-SHA256 + ChaCha20-Poly1305.
- **`suite = 2` is reserved for X-Wing (ML-KEM-768 + X25519 hybrid) HPKE.** A test pins that this build rejects suite 2 (`packages/core/test/fuzz.test.ts`).
- The wrapping context (purpose, scope) and the key grant signature (`keymember/key-grant/v1`) cover a hash of the wrapped key bytes, so they carry over unchanged regardless of suite.

## Migration steps

1. **Ship read support**: Implement suite 2 unwrap with `@hpke/hybridkem-x-wing` and ship it to every client (web, extension, CLI) first. Nobody writes suite 2 at this stage.
2. **Bump the keyset version**: Each member generates an X-Wing key pair and adds it to their public bundle (`keysetVersion + 1`, refreshed self-signature), and an admin re-certifies them. The certificate includes the X-Wing public key, and directory verification only accepts the certificate for the current version (already implemented).
3. **Switch writes**: When the recipient's certificate has an X-Wing key, new wrappings use suite 2. Group keys and the recovery key get X-Wing key pairs the same way and are rotated.
4. **Re-wrap**: Run key rotation on each vault to generate a new vault key. Simply re-wrapping would leave the old X25519 wrapping in DB backups and expose the old key, so this must be a **rotation that replaces the key itself**. Past item versions that were already exposed cannot be recovered.
5. **Lock down**: Once every member has finished step 2, new suite 1 wrappings are rejected. Migrating the signature algorithm (ML-DSA or similar) is planned separately.

## Cost and triggers

- Every member must be re-certified and every vault key rotated. At about 30 people this can be done within a day.
- When to start: when major browsers and operating systems start using ML-KEM by default, or when an audit or regulatory requirement arises. Until then we only maintain this document and the suite reservation.
