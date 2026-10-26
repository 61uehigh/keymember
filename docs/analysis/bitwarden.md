# Bitwarden analysis

> What was analyzed
> - Source: `bitwarden/clients@dbe1331`, `bitwarden/server@d6efd3b`, `bitwarden/sdk-internal@06f2c6f` (as of 2026-10-20 to 21)
> - Release build: Chrome extension `dist-chrome-2026.10.0.zip` (official GitHub release)
>
> Rule: **borrow the design, never the code.** ([ADR-000](../design/decisions.md))
> Path prefixes: `S/` = server, `C/` = clients, `SDK/` = sdk-internal/crates

## 0. Release build check (REA)

To confirm that the source matches what actually ships, we statically analyzed the official Chrome extension release with REA. No code was executed.
- REA Evidence: `ev_6aca1f7d948fb7ad6cb9df8719a28383c60f1d47f655bf6be0251b57c1119a98`
- Scope: `manifest.json` and `background.js` only. The other 107 of the 109 files are out of scope.

| Observation | What it means |
|---|---|
| MV3. `host_permissions: https://*/*, http://*/*` | It can inject content scripts into any site |
| Only 2 static content scripts. One of them runs with `all_frames` + `document_start` and only signals a request for injection | The real autofill code is **injected dynamically, on demand,** by the background via `chrome.scripting` |
| CSP `script-src 'self' 'wasm-unsafe-eval'`, a 7.8 MB WASM module | Crypto has moved into the **Rust SDK (WASM)** |
| SDK functions imported by `background.js`: `purecrypto_make_user_key_xchacha20_poly1305`, `wrap/unwrap_symmetric_key`, `encapsulate/decapsulate_key_unsigned`, `verify_and_unwrap_signed_public_key`, `rsa_*`, etc. | The V2 key scheme (XChaCha20 user key, signed public keys) **is in the release build too**. RSA is still in use alongside it |
| `use_dynamic_url: true` on `web_accessible_resources` | Stops web pages from fingerprinting whether the extension is installed |
| Contains the PBKDF2 constant `600000` (`6e5`) | Matches the default in the source |
| The Public Suffix List is bundled | URI matching is based on eTLD+1 |

## 1. Cryptography and key hierarchy

### KDF

- PBKDF2-SHA256 (600k iterations by default) or Argon2id (t=6, m=32 MiB, p=4). `SDK/bitwarden-crypto/src/keys/kdf.rs:142-173`
- The salt is the lowercased email. Work is under way to split it into a `MasterPasswordSalt` column. `S/Core/Entities/User.cs:115,138-140`
- **The downgrade floor is far too low.** The server-side minimum is 600k, but the client only rejects a prelogin response below **5,000**, so a malicious server can drop it to 5k. `C/libs/legacy-crypto/src/models/kdf-config.ts:19`
- For unregistered emails the server returns a fake KDF and salt derived from HMAC(email), so you cannot tell whether an account exists. `S/Identity/Controllers/AccountsController.cs:256-279`

### Key derivation chain

```
MK  = KDF(password, email)
SMK = HKDF-Expand(MK, "enc") ‖ HKDF-Expand(MK, "mac")       # 64B
UK  = random (V1: AES-CBC + HMAC 64B / V2: XAES-256-GCM, COSE)
User.Key = Enc_SMK(UK)
auth_hash = PBKDF2(password = MK, salt = password, 1 iteration)  # sent to the server
stored on server = ASP.NET Identity PasswordHasher(auth_hash, 100k)
```

- `SDK/bitwarden-crypto/src/keys/master_key.rs:24-27,72-95,166-187`
- **Weakness**: auth_hash is a deterministic function of MK. An attacker with a DB dump can attempt cracking at **one KDF run per guess**. This is not a PAKE.

### Ciphertext formats (EncString)

| type | Scheme | Status |
|---|---|---|
| 0 | AES-256-CBC, no MAC | Decrypt only (legacy) |
| 2 | AES-256-CBC + HMAC-SHA256 | Current workhorse. **No AAD and no key ID**, so ciphertexts can be swapped between fields |
| 7 | COSE_Encrypt0 (XChaCha20-Poly1305, XAES-256-GCM, etc.) | Recommended V2 format. Includes a key ID, supports padding |
| 3–6 | RSA-2048-OAEP (only type 4, with SHA-1, is actually generated) | Used for sharing and escrow. **Unsigned** |

- Sources: `SDK/bitwarden-crypto/src/enc_string/symmetric.rs:46-155`, `asymmetric.rs:44-111`
- **V2 improvements**: ML-DSA-44 and Ed25519 signing keys, `SignedPublicKey`, a signed `SecurityState` (a monotonically increasing version that prevents downgrades), and a "blob" format that bundles an item's fields into a single COSE object.
  - `SDK/bitwarden-core/src/key_management/{account_cryptographic_state,security_state}.rs`

### Sharing, recovery and devices

- **Organization key**: 64 random bytes. Wrapped with each member's RSA public key and stored in `OrganizationUser.Key`.
  - The **only basis for trusting a member's public key is a fingerprint (EFF words) compared by hand**.
- **Admin account recovery**: at enrollment the UK is wrapped with the organization public key (`ResetPasswordKey`).
  - **Any admin holding the organization key can obtain a member's entire UK.** `S/Core/AdminConsole/Entities/OrganizationUser.cs:48`
- **Emergency access**: the waiting period is enforced **by server policy only**.
- **TDE**: generates a per-device device key and RSA key pair. Admin approval reuses the `ResetPasswordKey` chain.
- **Changing the password or KDF does not rotate the UK.** Rotating the UK requires re-encrypting everything at once, and the RSA key cannot be rotated in the process.

### Tokens and 2FA

- OAuth2 ROPC on IdentityServer. Access tokens last 1 hour; refresh tokens are **reusable and sliding** (60 days on mobile, 30 on desktop). `S/Identity/IdentityServer/StaticClientStore.cs:27-35`
- 2FA: TOTP, Email, Duo, YubiKey, WebAuthn, recovery codes.
- New devices are verified with an email OTP, but users can turn this off.

## 2. Server architecture

- **Multiple .NET services**: Api, Identity, Admin, Events, Notifications (SignalR), Icons, Billing. The commercially licensed parts are Sso, Scim and PAM.
- **DB**: they **maintain both** MSSQL (Dapper, stored procedures) and EF Core (Postgres, MySQL, SQLite), which effectively means two repository implementations.
- **Self-hosting**: docker-compose brings up 11+ containers plus nginx.

### Data model

| Entity | Key points |
|---|---|
| Cipher | `UserId` or `OrganizationId`, `Type` (plaintext), `Data` (per-field EncString JSON), `Key` (item key), `Favorites`/`Folders` (per-user JSON maps), `DeletedDate` |
| OrganizationUser | role (Owner, Admin, User, Custom), status (Invited → Accepted → **Confirmed**). The organization key is wrapped on confirmation |
| Collection | The only unit of sharing. Names are encrypted with the organization key |
| CollectionUser/Group | `ReadOnly`, `HidePasswords`, `Manage` flags. **`HidePasswords` is enforced only on the client** |
| Policy | One per type per organization. About 20 types (require 2FA, disable personal vault, maximum vault timeout, etc.) |
| Event | 1000s for users, 1100s for items, 1500s for members, 1700s for policies, etc. |

**Left in plaintext on the server**: item type, folder and favorite mappings, modification times, URI match type, autofill settings, attachment sizes, password change time.

### Sync

- **`GET /sync` always returns a full snapshot.** Clients compare a date watermark from `GET /accounts/revision-date` and only call it when something changed.
- **SignalR pushes** carry only metadata such as `{id, revisionDate}`; the client then re-fetches.
- **Conflicts**: a write is rejected if the client's `LastKnownRevisionDate` differs from the server's by more than 1 second. **If the client omits it, last write wins.** `S/Core/Vault/Services/Implementations/CipherService.cs:963-973`

### Licensing

- The `bitwarden_license/` directory (SSO, SCIM, Providers (MSP), Secrets Manager, PAM) is under a **commercial license**.
- The rest of the server is AGPL-3.0; the clients are GPL-3.0.
- Policies, groups, event logs and account recovery live in the AGPL code but are switched on and off by a license file.

## 3. Browser extension and autofill

### Architecture

- When the MV3 service worker gets a signal from a static script, it injects the real code dynamically via `chrome.scripting`.
- Privileged messages are checked with `senderIsInternal` (extension origin and top frame).
- When the popup requests autofill it **passes only the item ID**, and the background looks the item up again, so decrypted data never crosses the message channel.
- The **decrypted vault cache** is encrypted with an ephemeral key held in `storage.session` and written to **`storage.local` (disk)**, because of the size limit on session storage.
- With the timeout set to **"Never"**, the **UK is stored on disk as base64**: security traded for convenience.

### Form detection

- Every field gets an opaque `opid`. Metadata and 6 kinds of label heuristics are collected, and collection reruns via MutationObserver.
- Autofill runs as a script of `[fill_by_opid, opid, value]` steps.
- It reaches into closed shadow roots (`chrome.dom.openOrClosedShadowRoot`).
- Sandboxed iframes are never filled.
- The heuristic keyword dictionary is 1,100 lines long. Per-domain selector rules ("fill assist") are fetched from the server.

### Inline menu clickjacking defenses

- The extension-origin iframe is wrapped in a **closed shadow root** and shown in the `popover` top layer.
- The menu closes if the page's `html`/`body` opacity is 0.6 or lower. It detects other elements covering the menu and blocks when changes come in a burst.
- **Input where `event.isTrusted` is false is rejected.** Each tab uses a random port key.
- **Passwords are never sent to the menu iframe.** Only names and usernames go there; the background performs the actual fill by ID.

### URI matching

| Type | Description |
|---|---|
| Domain (default) | Compared using tldts and the PSL. Private domains are honored, so `github.io` subdomains are treated as distinct |
| Host | Same host and port |
| StartsWith | Prefix of the raw string. **Not origin-aware** |
| Exact | Exact string match |
| Regex | **No ReDoS protection and no anchoring** |
| Never | Never matches |

Separately there are "equivalent domain" groups (server-wide plus user-defined).

### Phishing defenses

- No autofill on page load in untrusted iframes (cross-origin to the top frame and not matching the item). A manual fill there shows a `confirm()` warning.
- Filling an item saved with HTTPS into an HTTP page shows a `confirm()` warning.
- Right before filling it re-checks that the tab URL is unchanged and that the tab is the **visible (foreground) tab**.
- Autofill on page load is **off by default.**

### Passkeys

- Hooks `navigator.credentials` in the MAIN world. The origin is computed in the isolated content script.
- Accepts ES256 only. The P-256 private key is stored as PKCS#8, encrypted inside the item.
- **Weaknesses**: the background trusts the origin reported by the content script as is. The sign counter is fixed at 0.

### Other features

- **Save/update password prompts**: on form submission it uses `webRequest` to confirm the POST succeeded, then shows the prompt.
  - Meanwhile the **plaintext password sits in an in-memory queue for up to 150 seconds.**
- **Clipboard**: cleared automatically via an alarm, but only if the clipboard still holds the copied value.
  - If the service worker restarts, the record of what to clear is lost.
- **Generator**: 14 characters by default. Passphrases are 6 words from the EFF word list (7,776 words).
- **Desktop biometrics integration**: an RSA handshake over native messaging, with **no pairing confirmation shown to the user.**

### Maintenance burden

- Huge files: `overlay.background.ts` at 3,772 lines, `autofill.service.ts` at 3,332, and so on. `autofill/` contains 56 TODOs and FIXMEs.
- Code for the MV3 lifecycle is complex: a "thermal" state machine for tabs, re-injection after service worker restarts, and more.

## 4. What keymember takes from it

### Adopt as is

1. **Dynamic injection**: static scripts only signal; the real code is injected on demand.
2. **opid-based fill script** with a single commit point. Re-check the URL and foreground state right before committing.
3. **Inline menu isolation**: extension iframe, closed shadow root, top layer, `isTrusted` checks, no passwords sent to the menu.
4. **PSL-based eTLD+1 matching**, blocking sandboxed iframes, HTTP downgrade warnings.
5. **ID-only push hints**, no account enumeration via prelogin, per-item keys.
6. **The V2 direction**: AEAD (XChaCha20), signed public keys and security state, encrypting fields as one bundle.

### Improve on

| Bitwarden | keymember |
|---|---|
| The auth hash can be cracked from the DB | Uncrackable thanks to the Secret Key (2SKD) |
| KDF downgrade floor of 5k | Floor hardcoded at the default level |
| RSA-OAEP-SHA1, unsigned sharing | X25519 HPKE with admin-signed attestations |
| No AAD in type 2 | AAD binds to vault, item and field |
| A single admin can obtain the whole UK | Only the VK is rewrapped, with two-person approval |
| Plaintext metadata (type, folder, match type) | Encrypted inside the overview |
| Last write wins without a base date | `base_revision` required; 409 on mismatch |
| Reusable refresh tokens, 60 days | Rotated on every use, with reuse detection |
| Timeout "Never" stores the UK on disk | No such option. Maximum timeout enforced by policy |
| No ReDoS protection for regex matching; StartsWith works on the raw string | No regex matching. Matching is origin-based |
| Plaintext passwords sit in a queue for 150 seconds | Encrypted with a session key before queuing, with a short TTL |
| Passkey origin taken from the content script's report | Cross-checked against `sender.origin` |
| No pairing confirmation for desktop integration | Confirmed with a pairing code |
| Multiple services, two DB implementations | A single server and Postgres |
