# Architecture decision records (ADR)

Each entry has one of three statuses: `Proposed` is awaiting review, `Accepted` is agreed, and `Deferred` will be revisited later.

---

## ADR-000. Build from scratch instead of reusing Bitwarden code

- **Status**: Accepted
- **Decision**: Use Bitwarden only as a reference for structure and design, and **do not copy its code.**
- **Reasons**
  - The Bitwarden server is AGPL-3.0 and the clients are GPL-3.0. The `bitwarden_license/` directory, which holds SSO, SCIM, Secrets Manager and similar, is under a commercial license. Reusing the code would bring license obligations.
  - The Bitwarden server alone is 118 MB, with a lot of legacy compatibility code (type 0/2 EncString, RSA, parallel Dapper and EF maintenance).
  - A 30-person team needs only a fraction of its features.
- **Consequences**: We are free to choose our license, at the cost of more implementation work.

## ADR-001. Use TypeScript across the whole stack

- **Status**: Accepted (2026-10-22)
- **Decision**: Write the shared core, server, extension, web and CLI all in TypeScript. Cryptography uses `@noble/*` and HPKE (`@hpke/*`). Argon2id is fast enough in pure TS too (about 0.4 seconds at 64 MiB).
- **Alternatives**
  - **A. Build a Rust core for WASM and native.** This is where Bitwarden is heading with `sdk-internal`.
    - Pros: memory can be reliably zeroed, and mobile apps can use it as-is.
    - Cons: brings a new language into the team and complicates the build chain.
  - **B. Write only the server in Python (FastAPI).**
    - Pros: the in-house Python DDD conventions apply.
    - Cons: the server and clients cannot share protocol types.
- **Revisit when**: If there is a plan to build native mobile apps within a year, reconsider A.

## ADR-002. Adopt the Secret Key (2SKD)

- **Status**: Accepted (2026-10-22)
- **Decision**: As 1Password does, derive keys from the password combined with a 128-bit Secret Key.
- **Reasons**: Offline cracking stays impossible even if the server DB leaks. On a self-hosted server, operational mistakes (a leaked backup, for example) are relatively more likely.
- **Costs**
  - Enrolling a new device requires the Emergency Kit or an existing device.
  - An admin recovery feature is mandatory in case the key is lost (ADR-005).
- **Rejected alternative**: The Bitwarden approach (password only). If the DB leaks, each KDF run tests one guess, so security rests entirely on password strength.

## ADR-003. Authenticate without a PAKE (SRP/OPAQUE) in the MVP

- **Status**: Accepted (2026-10-22)
- **Decision**: Send `AUTH = HKDF(root, "auth")` over TLS, and have the server store only `SHA-256(AUTH)`.
- **Reasons**
  - AUTH includes the Secret Key's entropy, so storing its hash is not crackable.
  - SRP means a BigNum implementation and per-platform library maintenance.
- **Risk**: AUTH may be exposed at the TLS termination point. With it an attacker can log in but cannot decrypt. Mitigated by 2FA.
- **Revisit when**: The external security review flags it, or a mature TS implementation of OPAQUE appears.
- **Update (Phase 4.3)**: Replaced with a **signed challenge** instead of OPAQUE. An Ed25519 login key is derived from 2SKD, and the server stores only the public key. At login the client signs the server's one-time challenge together with the email, purpose and device. This gets OPAQUE's core benefits (neither the server nor the TLS termination point sees a reusable value, and a DB leak gives no verifier to log in with) without a new dependency. The Secret Key already provided OPAQUE's remaining benefit (resistance to offline guessing). It also avoids a WASM dependency and loosening the CSP (`wasm-unsafe-eval`). Existing accounts send the old value once at their next login and migrate.

## ADR-004. Use X25519 HPKE and Ed25519 instead of RSA

- **Status**: Accepted (2026-10-22)
- **Reasons**: As a greenfield project we have no legacy compatibility to keep. The keys are small and fast, with less room for implementation mistakes (padding and the like).
- **Follow-up**: Reserve suite IDs up front so we can move to a post-quantum hybrid (X-Wing).

## ADR-005. Use a Recovery Group for account recovery, with two-person approval

- **Status**: Accepted (2026-10-22)
- **Decision**: As 1Password does, admins only re-wrap vault keys. On top of that we add **two-person approval**.
- **Rejected alternative**: The Bitwarden approach (escrowing the user's User Key to the org public key). A single admin obtains all of the user's keys, so the exposure is broad.

## ADR-006. Certify public keys with admin signatures

- **Status**: Accepted (2026-10-22)
- **Decision**: When an admin confirms a member, the admin signs that member's public keys. Clients verify this signature before sharing.
- **Reasons**: Neither Bitwarden nor 1Password can stop a malicious server from substituting public keys (1Password white paper, Appendix C).
- **Costs**: Losing an admin key requires a procedure to repair the signature chain. Org creation enforces at least two admins.

## ADR-007. Defer SSO-based unlock to v2 or later

- **Status**: Deferred
- **Reasons**: 1Password's credential bundle and CPace, and Bitwarden's TDE and Key Connector, add a lot of complexity to key management. In the MVP, SSO is used only for identity verification at login.

## ADR-009. Sign key grants and invites

- **Status**: Accepted (2026-10-22, from the internal security review)
- **Decision**: When wrapping a vault key for someone, the grantor signs `{vaultId, generation, recipient, wrapped key hash}`, and the recipient accepts only grants signed by themselves or by a certified member. When inviting, the admin signs the email and role, and certification takes the role from this signature rather than from the server. Recovery requests are also signed over the target user by the requesting admin.
- **Reasons**: HPKE base mode does not authenticate the sender. Anyone can wrap a key to a public key, so without a signature the server could insert a vault key it knows and read secrets stored afterwards. The server could also have swapped roles and recovery targets.
- **Residual risk**: Only the server knows whether the grantor has manage permission on the vault. Collusion between a certified member and the server is not prevented ([review notes](../security/review-2026-10.md)).

## ADR-010. Replace fingerprint comparison with a secret in the invite link

- **Status**: Accepted (2026-10-25)
- **Decision**
  - The invite link's URL fragment (the part after `#`, which browsers do not send to the server) carries a secret and the root the admin trusts (the owner's signing key).
  - The secret is derived from the admin's signing key and the signed invite (`inviteLinkSecret`), so any of that admin's devices can recompute it without storing it.
  - The new member uses this secret to attach a MAC (`inviteProof`) to the public keys they upload. The admin's app checks it and signs the certificate automatically (`certifyInvited`).
  - Automatic certification is narrow: only for regular member invites, only within 14 days of the signed `issuedAt` (7 days of invite validity plus 7 days of slack), only when exactly one account signed up with that nonce, and only for a first key (`keysetVersion` 1) with no prior certificate. Admin invites always require fingerprint comparison, since admins receive a copy of the recovery key. When the conditions are not met, the app reports that fingerprint verification is required.
  - The new member pins the link's root as-is. They sign this root with their own signing key and store it on the server (`keymember/trusted-roots/v1`), and their other devices fetch the root after opening the keyset and verifying that signature.
  - The admin sends the link from their own mail app or Slack. If the server sent the email it would see the secret, so the server never sends it.
- **Reasons**: Having people read out and compare fingerprints is the biggest source of friction for a small team. 1Password skips this check and Bitwarden makes it optional. This approach keeps the check but makes it automatic.
- **Residual risk**
  - If the link is opened in a web page served by the server, that page's JavaScript can read the fragment. A malicious server can therefore see the secret on the web sign-up path and swap the keys and the root. This is the same exposure as the web vault's inherent limit (T6). The guarantee that "an attacker must control the server and email/Slack **at the same time**" holds only when the link is opened in a client the server does not serve (`keymember signup --link`).
  - Anyone holding the link can sign up with that email until it expires.
  - Manual fingerprint comparison remains for sign-ups that entered only a token without the link, for admin invites, and for devices that have not stored the root.

## ADR-008. Sync uses integer revisions and deltas, with conflicts returned as 409

- **Status**: Accepted (2026-10-22)
- **Reasons**
  - Bitwarden uses date-based watermarks and always does a full sync, which is prone to clock skew problems.
  - Without a base revision, Bitwarden lets the last writer win, so data in shared vaults can be silently overwritten.
