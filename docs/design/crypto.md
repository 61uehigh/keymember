# Cryptographic design

> Status: **Draft (needs review)**. This design assumes one external security review before code is written.
> Sources: [Bitwarden analysis](../analysis/bitwarden.md), [1Password analysis](../analysis/1password.md)

## Design principles

1. **Zero-knowledge**: The server holds no plaintext, no keys, and nothing that can be used for an offline guessing attack.
2. **A full leak of the server database must not enable cracking.** We adopt 1Password's 2SKD.
3. **Assume a malicious server.** The client blocks public key substitution and KDF parameter downgrades. Both products are weak here.
4. **Bind ciphertext to its context (AAD).** Moving a ciphertext to a different field or item must make decryption fail. This fixes the weakness of Bitwarden type 2.
5. **Standard primitives only.** No home-grown cryptography. Formats carry algorithm identifiers so versions can be bumped.

## 1. Primitives

| Purpose | Choice | Notes |
|---|---|---|
| Password KDF | **Argon2id** | Defaults m=64 MiB, t=3, p=1. The client **hardcodes** a floor (§2) |
| Key separation | HKDF-SHA256 | info labels use the form `keymember/<purpose>/v1` |
| Symmetric AEAD | **XChaCha20-Poly1305** | The 192-bit nonce makes random nonces collision-safe |
| Key encapsulation | **HPKE (RFC 9180)**, DHKEM(X25519) + HKDF-SHA256 + ChaCha20-Poly1305 | A suite ID allows a later move to the X-Wing (X25519 + ML-KEM-768) hybrid |
| Signatures | **Ed25519** | Signs public keys, security state and group member lists |
| Randomness | OS CSPRNG (`crypto.getRandomValues`, `getrandom`) | |
| Constant-time comparison | Library function | Used for comparing tokens and MACs |

**No RSA.** Bitwarden still uses RSA-2048 OAEP-SHA1 and 1Password uses RSA-2048. As a greenfield project we have no legacy compatibility to keep.

## 2. Account secrets: password and Secret Key

### Secret Key (1Password style)

- Generated on the client at sign-up. Format: `K1-<6-char account ID>-<26 random chars>`
  - Alphabet: `23456789ABCDEFGHJKLMNPQRSTVWXYZ` (31 characters, excluding the confusable 0/1/I/O/U)
  - About 128.8 bits of entropy
- Stored in the device's OS secure storage (Keychain, DPAPI, libsecret, the extension's `storage.local`) and in the **Emergency Kit PDF**.
- Never sent to the server.

### Key derivation

```
pw'   = NFKD(trim(password))
s     = account_salt (16 random bytes, stored on the server, returned by prelogin)

P     = Argon2id(pw', salt = s, m, t, p)                     → 32B
S     = HKDF(ikm = raw Secret Key bytes, salt = account_id, info = "keymember/secret-key/v1") → 32B
root  = HKDF-Extract(salt = "keymember/2skd/v1", ikm = P ‖ S)

AUK   = HKDF-Expand(root, "keymember/auk/v1", 32)    # encryption key that unlocks the account keyset
AUTH  = HKDF-Expand(root, "keymember/auth/v1", 32)   # for server authentication
```

**Differences from Bitwarden and 1Password**

| Aspect | Bitwarden | 1Password | keymember |
|---|---|---|---|
| Salt | Email (being split out into a `MasterPasswordSalt` column) | HKDF(random 16B, email) | **Random 16B only**. Changing the email does not require re-deriving keys |
| KDF | PBKDF2 600k (Argon2 optional) | PBKDF2 650k (browser constraints) | **Argon2id**, via WASM |
| Auth value | PBKDF2(MK, pw, **1 iteration**). Crackable if the DB leaks | SRP verifier plus Secret Key | AUTH (128+ bits, since it includes the Secret Key) |
| Encryption/auth key separation | A single PBKDF2 iteration, no HKDF | Two KDF runs with separate salts | **One KDF run + separate HKDF labels** |

### Server authentication

> **Since Phase 4.3, login uses a signed challenge.** An Ed25519 login key is derived from the 2SKD root with `HKDF-Expand(root, "keymember/login-signing/v1")`, and the server stores only the public key. prelogin issues a one-time challenge (2 minutes) and the client signs `{purpose, email, challengeId, challenge, deviceId}` (domain `keymember/login/v1`). Password changes use the same scheme with `purpose = change-password`. What follows is the legacy scheme that an account goes through once before migrating ([ADR-003](decisions.md)).

AUTH includes the 128 bits of entropy in the Secret Key, so even with the server storing `H = SHA-256(AUTH)`, **an offline guessing attack is not possible at all.**
- For this reason the MVP does **not** use a PAKE such as SRP or OPAQUE, avoiding the BigNum and SRP maintenance cost that 1Password carries.
- Risk: whatever terminates TLS (a proxy, for example) can see AUTH. Holding AUTH lets an attacker **log in but not decrypt** (there is no AUK).
  - Mitigation: 2FA is mandatory, and new devices require approval (§8).
  - Follow-up: replacing this with OPAQUE (IRTF CFRG) is left open in an [ADR](decisions.md).
- The server verifies with `constant_time_eq(SHA-256(AUTH), stored)`.

### Preventing KDF parameter downgrades

- The client code **hardcodes a floor**: Argon2id m ≥ 64 MiB, t ≥ 3. If the prelogin response is below this, the client aborts immediately.
  - In Bitwarden the server-side minimum (600k) differs from the client's rejection floor (5k), so a malicious server can lower it to 5k.
- For unregistered emails the server returns a fake salt and parameters derived from `HMAC(server_secret, email)`, so registration status cannot be probed (as Bitwarden does). 1Password acknowledges this as one of its own weaknesses.

## 3. Key hierarchy

```
AUK
 └─(AEAD)─► Account Key (AK, 32B random)
              ├─(AEAD)─► encryption private key  X25519   (public key stored in plaintext on the server)
              ├─(AEAD)─► signing private key     Ed25519  (public key stored in plaintext on the server)
              └─(AEAD)─► personal Vault Key

Vault Key (VK, 32B random)  ── HPKE ──► X25519 public key of each member / group / Recovery Group
 └─(AEAD)─► Item Key (IK, 32B random, one per item)
              ├─(AEAD)─► overview  {title, urls[], tags, type, icon-hint}
              ├─(AEAD)─► details   {username, password, totp, notes, fields[], passkeys[], history[]}
              └─(AEAD)─► attachment key ─► file chunks
```

- **Changing the password** only re-wraps AK under the new AUK. It is cheap.
- **"Regenerate keyset"** is a separate feature. It creates a new AK and new private keys and re-wraps the VKs. It addresses weakness A.5 acknowledged by 1Password (changing the password leaves the keyset unchanged).
- **overview and details are separate** (1Password style). Listing, search and URL matching decrypt only the overview.
- **Each item has its own key** (Bitwarden's cipher key approach). Moving an item to another vault only re-wraps its IK.

## 4. Ciphertext format (Envelope)

```
Envelope = CBOR {
  v:     1,                 # format version
  alg:   1,                 # 1 = XChaCha20-Poly1305
  kid:   bytes(16),         # ID of the key that sealed this data
  nonce: bytes(24),
  ct:    bytes              # ciphertext ‖ tag
}
AAD = "keymember/v1" ‖ kind ‖ owner_id ‖ object_id ‖ field
```

- Example `kind` values: `item.overview`, `item.details`, `vault.key`, `attachment.chunk`.
- The AAD includes the vault ID, item ID and field name, so **if the server swaps a ciphertext into another item or field, decryption fails.**
- Plaintext is serialized as CBOR and then **padded to a multiple of 32 bytes** so its length does not reveal its content (as in Bitwarden's V2 blob).
- File attachments are encrypted with a separate AEAD per 64 KiB chunk, with the chunk index and a last-chunk flag in the AAD (the STREAM construction).

## 5. Sharing and public key trust

Bitwarden and 1Password share a weakness: **they cannot stop the server from substituting public keys.** keymember is an internal company tool, so it prevents this as follows.

1. **Users sign their public key bundle.** Each user signs `{user_id, x25519_pub, ed25519_pub, version}` with their own Ed25519 key (self-signed).
2. **The org directory is signed.** When an admin confirms a member, the admin **signs** `{org_id, user_id, email, x25519_pub, ed25519_pub, confirmation time}` **with their own Ed25519 key**. This signature acts as a certificate.
3. **The client verifies.** Before sharing, the client checks that the recipient's public key carries "a signature from a trusted admin".
   - Admin public keys themselves are pinned when the org is first created, and later ones can only be added by an admin's signature.
4. **Fingerprints are shown.** Five words derived from a hash of the public key are displayed. When confirming a member, the UI prompts the admin to compare them in person or over Slack.

**Invite links and the trust root** ([ADR-010](decisions.md)): The invite link's fragment carries a one-time token, the email, a link secret and the root. The link secret is `HMAC-SHA256(HKDF(admin signing seed, "keymember/invite-link-key/v1"), CBOR(["keymember/invite-link/v1", signed invite]))`, and each invite includes a random nonce so the value differs every time. The new member attaches `HMAC-SHA256(link secret, CBOR(["keymember/invite-proof/v1", userId, x25519_pub, ed25519_pub]))` to the sign-up request. The inviting admin's app recomputes the secret, checks this value against the public keys the server presents, and signs the certificate only if they match. This happens automatically only for a regular member invite, within 14 days of the signed `issuedAt`, when exactly one account uses that nonce, and for a first key with no prior certificate. Everything else falls back to fingerprint comparison. The web sign-up page is served by the server, so on the web path this guarantee drops to trusting the server (T6). The roots a user pins are signed by the user's own signing key as `{userId, orgId, roots, issuedAt}` (`keymember/trusted-roots/v1`) and stored on the server; a new device accepts them only after opening the keyset with the password and Secret Key and verifying this signature. If account recovery replaces the keys, the stored roots are cleared.

**Grant signatures** ([ADR-009](decisions.md)): Each time a vault key is wrapped for someone, the grantor signs `{vaultId, keyGeneration, principalType, principalId, SHA-256(wrappedKey)}` (`keymember/key-grant/v1`). Sync accepts only grants signed by the user themselves or by a member whose certificate chains to a pinned root, and uses a group private key only after verifying an admin-signed group certificate. Invites (`keymember/member-invite/v1`) and recovery requests (`keymember/recovery-request/v1`) are also signed by an admin, and completing certification or recovery uses these signed values rather than values sent by the server. Recovery public keys are accepted only when signed by a pinned root (the owner).

**Groups** (1Password style): A group has an X25519 key pair. The group private key is HPKE-wrapped to each member and to the recovery key (context `group-private-key`, `[groupId, key version, holder]`), and vault keys are wrapped to the group public key. The group signing key was dropped during implementation, since groups never need to sign anything.

- **Group certificate**: An admin signs `{orgId, groupId, name, x25519_pub, key version, issuer, issued at}` (domain `keymember/group-certificate/v1`). The client wraps a vault key to a group only after verifying an admin signature that chains to a root and that the key and version match what the server returned. If the server substitutes a group key, sharing fails.
- **Version pinning**: Wrapping a vault key to a group also sends the group key version. If the group key has rotated in the meantime, the server rejects the request with 409. This prevents copies wrapped to a rotated-out key from lingering where no one can open them.
- **Adding a member**: The current group key is wrapped to the new member. An admin who is not in the group opens the group key through the recovery key copy.
- **Removing a member = rotating the group key**: Generate a new key pair, re-wrap it to the remaining members and the recovery key, and re-wrap every vault key the group holds (current generation) to the new group public key. The server checks that every vault the group can access has been re-wrapped at the current generation. Rotation is done by the admin who manages the group, so the admin rewrites the group's wrapped rows even without `manage` permission on those vaults. This does not widen admin power: the server only allows rows the group already has to be replaced, with the same permissions and the same current generation. And the admin could already add people to or remove them from those vaults by changing the group's membership, and can open the group key through the recovery key. The rewritten copies carry the admin's grant signature, and since the admin is a member whose certificate chains to a root, sync accepts them.
- **Membership signature**: When an admin wraps the group private key to a member, the admin signs `{groupId, key version, userId, SHA-256(wrapped private key)}` (`keymember/group-membership/v1`).
- **Re-verify on rotation**: Vault key rotation and group key rotation do not trust the roster the server provides. The client wraps the new key only to recipients with a grant signature (vault) or membership signature (group) it has verified. Recipients with no signature, or one that fails verification, are left out, and including them requires the caller to opt in explicitly (`keepUnverified`). So even if a malicious server slips someone in during a rotation, the rotating admin does not sign for them. Group members added before these signatures existed count as unverified and must be added again.
- **Residual risk**: A removed member may remember vault keys received before removal. Rotating the vault key itself is done separately with each vault's "rotate key" action (for the same reason as member removal, the admin decides the cost and scope).

**Key rotation when removing a member** (addresses 1Password weakness A.4):
- Default behavior: the server stops delivering data to that member and **moves the vault key to the next generation.**
- From then on, newly created or modified items wrap their IK with the new VK (lazy rotation).
- There is also a "re-encrypt everything now" button. With few items this is cheap, since only the IKs need re-wrapping.

**Share links** (Phase 4.2): Sending a single item outside a vault does not use the vault key.

- Each link gets a fresh 32-byte secret `S`. With a view password, `P = Argon2id(password, SHA-256("keymember/share/v1/" ‖ id))` (same cost as accounts); without one it is empty.
- `root = HKDF-Extract(salt = "keymember/share/v1/" ‖ id, S ‖ P)`, from which an encryption key and an access proof are each derived with HKDF-Expand. The snapshot is sealed with XChaCha20-Poly1305 under the encryption key, with the share id in the AAD.
- The server stores only `SHA-256(access proof)`. It returns the ciphertext and decrements the view count only when the access proof is presented. So someone who knows only the id (link previews, logs) cannot use up views, a wrong password does not decrement the count, and 10 wrong attempts close the link.
- `S` lives only in the URL fragment (`#/share/<id>?k=…`), so it never appears in server or proxy logs. When the views run out or the link expires or is revoked, the server deletes the ciphertext.

## 6. Account recovery

There are three design goals: admins must be able to recover accounts, **admins must not see users' passwords or personal data while doing so**, and any abuse of recovery must show up in the audit log.

**Recovery Group approach** (1Password style, with added safeguards):
- The VK of every **shared vault** is also wrapped to the Recovery Group public key.
- **Personal vaults are optional.** Org policy decides whether "personal vaults of company accounts are also recoverable". The default is yes, since they are company assets.
- Recovery procedure:
  1. Admin A requests recovery.
  2. **A different admin B approves** (two-person approval, which 1Password lacks).
  3. The target user's account is suspended.
  4. If the user logs in with their existing password, recovery is cancelled automatically.
  5. The user re-registers with a new password and a new Secret Key and creates a new keyset.
  6. The server sends the admin the VKs wrapped to the Recovery Group and the user's new public keys (with signature verification).
  7. The admin's client re-wraps the VKs to the user's public key.
- The whole recovery process is recorded in the audit log, and all admins are notified.

In Bitwarden's account recovery, **a single admin obtains the user's entire User Key.** keymember only re-wraps VKs, so the exposure is narrower.

**Implementation notes (Phase 2)**

- The owner creates the recovery key when initializing the org. The owner signs its public key, and its private key is HPKE-wrapped to each admin. When an admin is certified, the certifying admin hands over a copy.
- The client wraps a VK only after verifying the recovery public key's signature through the trust chain. If the server substitutes the recovery key, vault creation itself fails.
- The approving admin receives a **one-time recovery token** (3 days) and passes it to the user directly. The user registers a new password, a new Secret Key and a new keyset (version +1) under the same user id. TOTP is reset at this point too.
- The new keys must be **certified** again (fingerprint comparison). Only after certification can the admin complete recovery, which restores exactly the vaults and permissions the user had when recovery was requested.
- **Admins cannot recover the owner account.** Every device pins the owner key as the trust root. The owner must not lose the Emergency Kit.
- Residual risk: if the approver and the certifier collude (two admins), the approver can use the token themselves and take over the user's place with their own keys. This is recorded in the audit log, and recovery is cancelled if the real user logs in with their original credentials (before re-registration).

## 7. Local lock and devices

- **Unlock**: Derive AUK from the password and the locally stored Secret Key, then decrypt AK. Works offline.
- **Biometrics and PIN**:
  - A random per-device Device Unlock Key (DUK) wraps AK, stored locally.
  - The DUK lives in OS secure storage (Secure Enclave, TPM, Keychain) and is released by biometrics.
  - With a PIN, `Argon2id(PIN)` wraps the DUK. **It is deleted after 5 failed attempts.** Nothing is stored on the server.
- **Auto-lock**: Org policy enforces a maximum timeout. On lock, AK, VK and IK are cleared from memory (in JS this only goes as far as dropping references).
- **Clipboard**: Cleared automatically after 30 seconds, with the flag set to exclude it from clipboard history.

## 8. Authentication, sessions and device enrollment

- **Login**: `prelogin(email)` → returns `{salt, kdf_params, challengeId, challenge}`, followed by `login(email, challengeId, signature, device_id, 2FA)`. Unknown emails get a response and challenge of the same shape.
- **2FA**: TOTP and WebAuthn are supported. Org policy **makes it mandatory by default**.
- **New devices**: A device without the Secret Key is enrolled with the QR code from the Emergency Kit or by approval from an existing device. Existing-device approval is a simplified version of 1Password's CPace approach.
  - The existing device shows a 6-digit code and runs a **CPace PAKE** with the new device.
  - The Secret Key is sent under that session key. The server in the middle cannot see it.
- **Tokens**:
  - The access token is a 15-minute **opaque token**. The server stores only its SHA-256 hash, so a leaked session table yields no usable tokens, and tokens can be revoked immediately. This replaced signed JWTs during implementation.
  - The refresh token **rotates on every use**, and if reuse is detected the whole session family is revoked.
  - Bitwarden keeps refresh tokens reusable and uses a 60-day sliding window on mobile. This improves on that.
- **SSO** (Phase 4.1): Verifying the company Google account is a step **in addition to** the authentication above. It plays no part in AUK, AK or vault keys. The ID token is checked for its signature (JWKS), `iss`, `aud`, `exp`, `nonce`, `email_verified` and `hd`, and the email must match the keymember account. The Google `sub` is bound to the account on first verification, so if the same email is later reassigned to a different Google account it does not pass. Stored Google refresh tokens are sealed with XChaCha20-Poly1305 under a key derived by HKDF from a server secret (useless if only the DB leaks).
- **Security state version** (Bitwarden V2 style): A user-signed `{security_version}` lets the client refuse a server rollback to an older format.

## 9. What the server can see (metadata)

| Visible (plaintext) | Not visible (encrypted) |
|---|---|
| User email, name, public keys, signatures | Item title, URL, username, password, notes, tags, **item type** |
| Vault ID, item ID, modification time, padded size | Vault name |
| Membership and permission flags, group composition | Attachment names |
| Device info, IP, audit log | Password history |

Bitwarden leaves item type, folder mapping, URI match settings and attachment size in plaintext. keymember moves these into the overview.

## 10. Open issues

- [ ] When to adopt OPAQUE ([ADR-003](decisions.md))
- [ ] When to move to a post-quantum hybrid KEM (X-Wing). The migration path is set out in [pq-migration.md](pq-migration.md) and wrapping suite 2 is reserved
- [ ] Measure Argon2id 64 MiB performance in the browser extension (target under 1 second on a low-end laptop). About 0.4 seconds in pure TS (`@noble/hashes`) on Node 24 + M-series
- [ ] Schedule the external security review
