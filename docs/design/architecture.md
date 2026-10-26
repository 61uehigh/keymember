# Architecture

> Status: **Draft (needs review)**
> Target size: about 30 people in one company. **Operational simplicity and security** come before scalability.

## 1. Components

```
┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Browser ext. │  │  Web vault   │  │     CLI      │  │   (later)    │
│  (MV3)       │  │ (admin cons.)│  │ (developers) │  │desktop/mobile│
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────────────┘
       └──────── @keymember/core (crypto, models, sync) ────────┘
                              │ HTTPS (TLS 1.3)
                    ┌─────────▼─────────┐
                    │   keymember-server │  one process
                    │  API + WebSocket   │  (not split into 8 services like Bitwarden)
                    └─────────┬─────────┘
                ┌─────────────┼──────────────┐
          PostgreSQL     Object storage       SMTP / Slack
                        (S3/GCS, attachments) (invites, alerts)
```

**Where we depart from Bitwarden**

| Bitwarden | keymember | Why |
|---|---|---|
| 8+ services: Api, Identity, Events, Notifications, Icons, Admin, etc. | **A single server process** | At 30 people, the operational burden outweighs the benefits |
| Maintains **both** MSSQL (Dapper) and EF (Postgres, MySQL, SQLite) | **PostgreSQL only** | Avoids the cost of maintaining two storage layers |
| IdentityServer (OAuth2 ROPC) | Simple, in-house token issuance | No need to support third-party clients |
| Icon proxy server | Client fetches icons directly, or none at all | Keeps icon requests from revealing visited domains to the server |

### Server (`apps/server`)

Routes validate the request, check policy, then read and write through repositories. Routes and services get repository interfaces from the `Store`: `context.store.transaction(repos => …)` inside a transaction, `context.store.repositories()` outside one. Repositories return records in the server's own terms, not DB rows.

- `repositories/`: contracts only. Repository interfaces and record types, `Repositories`, `Store`.
- `repositories/pg/`: PostgreSQL/PGlite implementation (`Pg…Repository`, `pgRepositories`, `SqlStore`). All SQL lives here.
- `firestore/`: Firestore implementation (`Firestore…Repository`, `FirestoreStore`) and a document layer that buffers writes until commit.

`KEYMEMBER_STORE` picks the implementation at startup; `buildApp` only uses the `Store` it is given.

| Repository | Responsible for |
|---|---|
| `UserRepository`, `MembershipRepository`, `InviteRepository`, `OrganizationRepository` | Accounts, memberships and certificates, invites, org policies and recovery keys |
| `SessionRepository`, `LoginChallengeRepository`, `SsoRepository` | Logins (token pairs), signed login challenges, SSO tickets and links |
| `VaultRepository`, `ItemRepository`, `GroupRepository`, `ChangeFeedRepository` | Vaults and grants, items, groups, the change feed for sync |
| `ShareRepository`, `RecoveryRepository`, `AuditRepository` | Share links, account recovery, audit log |

### Client SDK (`packages/client`)

The web vault, extension, desktop app and CLI share one SDK. `Session` is the public entry point for a single login; the actual work is done by components, each with one responsibility.

| Component | Responsibility |
|---|---|
| `AuthorizedApi` | Sends requests with the access token; on a 401, refreshes once with the refresh token and retries |
| `TrustContext` | Starting from the pinned root, decides whose keys to trust: member certificates, group certificates, recovery keys, share recipients' keys |
| `VaultCache` | Synced vaults and items. Opens a vault key only through grants signed by a trusted person and certified group keys |
| `VaultSharing` | Creating, sharing, unsharing and rotating keys for vaults |
| `ItemWriter` | Creating, updating and deleting items |
| `ShareLinkIssuer` | Share links for people outside the vault |

Admin features come from `session.orgAdmin()`, `groupAdmin()` and `recovery()`. Each admin helper receives only the session internals it uses (`GroupAdminDeps`, etc.).

### Desktop app (Phase 4.5)

`apps/desktop` is an Electron app. The main process holds the TypeScript SDK session (the same role as the extension's background), and the window is a sandboxed React UI that makes requests only over a single channel (`keymember`) exposed by the preload. The main process validates requests with zod and checks that the sending frame is the bundled `index.html`. The main process serves an OpenSSH agent at `userData/agent.sock` and signs with keys from `ssh-key` items, asking the window for approval. Touch ID unlock uses a session snapshot sealed with Electron `safeStorage` (the macOS keychain) plus `systemPreferences.promptTouchID`.

The main process's vault is split by responsibility. `DesktopVault` owns only the session lifecycle (unlock, lock, owner pinning) and delegates everything else to injected components.

| Component | Responsibility |
|---|---|
| `DeviceConfigStore` | `config.json`: device id, server, pinned owner key, Secret Key sealed with the keychain |
| `BiometricUnlock` | Touch ID: sealed session snapshot (`unlock.bin`), expires after 2 weeks |
| `ClipboardGuard` | Copies a secret and clears it after 30 seconds (or on lock) if it is still there |
| `VaultKeyring` | Listing and adding `ssh-key` items, SSH agent identities and signing approval |

OS features (`platform.ts`) are split into small interfaces such as keychain, Touch ID and clipboard, and each component receives only the ones it uses. `createDesktopVault` is the only place that builds the real components; `DesktopVault` knows only their types. Tests therefore build the vault from fake components.

## 2. Tech stack (proposed, [ADR-001](decisions.md))

| Layer | Choice | Alternative |
|---|---|---|
| Shared core | **TypeScript** + `@noble/ciphers`, `@noble/hashes`, `@noble/curves` (audited, pure TS). Argon2id also comes from `@noble/hashes` | A Rust core built for WASM and native (the Bitwarden SDK approach) |
| Server | TypeScript (Node.js, Fastify) + PostgreSQL | Python (FastAPI), which would let us apply the in-house Python DDD conventions |
| Browser extension | MV3, TypeScript, React | |
| Web vault and admin console | React + Vite | |
| CLI | Node.js single binary | |
| Deployment | One container + managed Postgres (company AWS or GCP) | |

Using TypeScript everywhere lets the **server, extension, web and CLI share the crypto core and API types as-is**. Since the server never handles plaintext, though, the language choice matters relatively little there.

## 3. Data model

```
User ─┬─ Device
      ├─ Membership ── Organization ── Policy
      │      │
      │   GroupMember ── Group
      │
      └─ VaultAccess ── Vault ── Item ── Attachment
           (per User or Group)
```

| Entity | Key fields (🔒 = encrypted by the client) |
|---|---|
| **User** | id, email, name, account_id, kdf_params, salt, auth_hash, 🔒enc_account_key, enc_pub(X25519), sig_pub(Ed25519), 🔒enc_private_keys, self_signature, security_version |
| **Device** | id, user_id, name, type, last_seen, 🔒enc_device_unlock (optional), refresh_token_family |
| **Organization** | id, name, recovery_group_id, pinned_admin_keys |
| **Membership** | org_id, user_id, role(owner/admin/member), status(invited/accepted/confirmed/suspended), **admin_signature** (public key attestation) |
| **Group** | id, org_id, 🔒enc_name, enc_pub, sig_pub, kind(normal/recovery) |
| **GroupMember** | group_id, user_id, 🔒wrapped_group_private_key (HPKE) |
| **Vault** | id, org_id, kind(personal/shared), 🔒enc_name, key_generation |
| **VaultAccess** | vault_id, principal(user or group), 🔒wrapped_vault_key (HPKE), key_generation, permissions |
| **Item** | id, vault_id, revision, 🔒enc_item_key, 🔒enc_overview, 🔒enc_details, padded_size, deleted_at |
| **Attachment** | id, item_id, 🔒enc_meta, 🔒enc_file_key, object_key, padded_size |
| **ItemPerUser** | item_id, user_id, 🔒enc_folder/favorite. Moves what Bitwarden stored as a JSON map on the cipher into its own table |
| **AuditEvent** | id, org_id, actor, action, target, ip, device, at |
| **ShareLink** | id, item_snapshot(🔒), token_hash, expires_at, max_views, views, allowed_emails |

**Permission flags**: a simplified version of Bitwarden's collection permissions.

| Permission | Meaning | Enforced by |
|---|---|---|
| `view` | View and autofill | Cryptography (whether you hold the VK) |
| `edit` | Modify | **Server** (anyone with the VK can produce ciphertext, so the server rejects the upload) |
| `manage` | Manage members, share | Server + cryptography (the party that re-wraps the VK) |
| `hide_password` | Autofill only, without revealing the password | **Client only**. The UI states explicitly that it is "not a security boundary" |

Bitwarden's `HidePasswords` is also enforced only on the client. 1Password documents this as three levels of access control. keymember is likewise honest about the distinction in the admin console UI.

## 4. Sync

We start from Bitwarden's approach and add **incremental sync**.

- **Change detection**: a per-user `revision` counter (a monotonically increasing integer). Bitwarden uses dates; an integer avoids clock-skew problems.
- **`GET /sync?since=<revision>`**: returns the vaults, items and memberships changed since then, plus a list of deleted IDs. Without `since`, it returns everything.
  - Bitwarden always does a full sync. That is fine at 30 people, but incremental sync is cheap to implement.
- **Live updates**: the WebSocket sends **ID-only hints** such as `{type: "item.changed", vault_id, item_id, revision}` (the Bitwarden approach). The client then refetches.
- **Conflicts**: optimistic concurrency. Every update must include `base_revision`; if it does not match the server's value, the server returns `409`. The client shows the user both versions and lets them choose.
  - In Bitwarden, if the client omits the base date, the last write wins. keymember makes `base_revision` **required**.
- **Offline**: the client keeps an encrypted local cache. Offline edits are not supported in the MVP; offline is read-only.

## 5. API overview

```
POST /auth/prelogin            {email} → {account_id, salt, kdf}
POST /auth/login               {email, auth, device, otp?} → {access, refresh, enc_account_key, ...}
POST /auth/refresh             (rotation)
POST /auth/devices/link/*      (CPace relay, planned but not built)

GET  /sync?since=
GET  /users/:id/keys           → public keys + self signature + admin signature

POST /vaults                   PUT /vaults/:id/access   (upload VK wrappings)
POST /items                    PUT /items/:id (base_revision)   DELETE /items/:id
POST /items/:id/attachments    (issues a signed upload URL)

POST /orgs/:id/invites         POST /orgs/:id/members/:uid/confirm (admin_signature)
POST /orgs/:id/recovery/*      (request → two-person approval → re-enroll → re-wrap)
GET  /orgs/:id/audit
PUT  /orgs/:id/policies/:type

POST /share-links              GET /s/:id (token in a header, secret in the URL fragment)
WS   /ws
```

## 6. Organization policies (MVP)

Of Bitwarden's 20 or so policies, we pick only the ones a 30-person company needs.

| Policy | Default |
|---|---|
| Require 2FA | On |
| Maximum auto-lock time | 8 hours |
| Minimum master password strength (zxcvbn score) | 3 or higher |
| Disallow personal vault export | On |
| Allow share links / maximum expiry | Allowed / 7 days |
| Include personal vaults in recovery | On |

## 7. Audit log

- **Events recorded by the server**: login, failed login, 2FA changes, item create/update/delete, sharing changes, member changes, policy changes, recovery, export, share link creation and views.
- **Events reported by the client** (Bitwarden's `/collect` approach): password reveal, copy, autofill. The docs state explicitly that these come from the client and can be forged.
- **Retention**: 1 year. Searchable in the admin console and exportable as CSV.
- **Slack alerts**: high-risk events such as recovery requests, new admins and policy changes.

## 8. Integrations (later)

- **Google Workspace SSO** (implemented in Phase 4.1): used **for identity verification at login**, not for unlocking. Unlocking via SSO (1Password's credential bundle, Bitwarden's TDE) is complex, so it is deferred to v2 or later.
  - Flow: once a login passes password, Secret Key and 2FA, the server returns an **SSO ticket** (id + secret) instead of tokens. The client opens `/api/auth/sso/start?ticket=id` in the browser; the server redirects to Google and verifies the ID token at `/api/auth/sso/callback`. The client polls `/api/auth/sso/finish` with the ticket secret to receive the tokens. The secret never appears in the browser URL, so someone who only sees the URL cannot take over the session.
  - The server encrypts the Google refresh token with a key derived from a server secret and stores it per login (session family). Every time a keymember token is refreshed, it uses it to check that the account is still active.
  - Configured through the environment variables `KEYMEMBER_OIDC_ISSUER`, `KEYMEMBER_OIDC_CLIENT_ID`, `KEYMEMBER_OIDC_CLIENT_SECRET`, `KEYMEMBER_OIDC_HOSTED_DOMAIN` and `KEYMEMBER_PUBLIC_URL`.
- **SCIM**: low priority at 30 people. Offboarding is done by hand in the admin console.
- **Developer secrets**: environment variable injection such as `keymember run -- <cmd>`, and service accounts for CI. Modeled on 1Password's split-credential approach.
