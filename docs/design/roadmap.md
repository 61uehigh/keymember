# Scope and roadmap

## Goals

The goal is for **a company of about 30 people** to reach the point where:
- Shared passwords scattered across Slack, Notion and sticky notes are **gathered in one place.**
- **Access is cut off immediately when someone leaves.**
- **There is a record of who viewed what.**
- The development team manages SSH keys and `.env` secrets with the same tool.

## Non-goals

- Multi-tenant SaaS serving outside customers
- Native mobile apps (out of scope for v1)
- Unlocking via SSO (only login identity verification is supported)
- Family plans, billing, licensing

## Phases

### Phase 0. Design

- [x] Analysis of the Bitwarden source and shipped builds, and of the 1Password white paper
- [x] Draft designs for cryptography, architecture, threat model and autofill
- [x] Internal review: decided the open ADRs (001, 002, 003)
- Engaging an external security reviewer: moved to Phase 4.3

### Phase 1. Core and server (MVP-α) — Done

- [x] `@keymember/core`: KDF, 2SKD, envelope, HPKE, signatures, item model + **test vectors** (KDF vectors cross-checked against an independent Python implementation)
- [x] Server: sign-up, invites, login, 2FA (TOTP), devices, sync, vault and item CRUD, audit log
- [x] `@keymember/client`: protocol SDK. Wraps keys only after verifying the certificate chain
- [x] CLI: login, sync, lookup, `get`, `run -- <cmd>` (environment variable injection)
- [x] Emergency Kit PDF generation (with QR code)
- Deferred to later phases: vault key rotation after removing a member, and account recovery (done in Phase 2); CPace-based device linking (not done yet; on a new device, enter the Secret Key by hand or copy it from the Emergency Kit)
- Done when: a shared vault can be created with the CLI and two users can exchange items.

### Phase 2. Web vault and admin console (MVP-β) — Done

- [x] Web vault: item management, sharing, search, live TOTP codes, clipboard auto-clear, 15-minute idle lock
- [x] Admin console: member invites and confirmation (confirmed only after typing the fingerprint by hand), policies (require 2FA), audit log, **recovery (two-person approval)**
- [x] Vault key rotation: replaces the vault key and every item key when removing a member
- [x] Import: Bitwarden JSON, 1Password 1PUX, Chrome CSV (both CLI and web)
- [x] The server serves the web build with a strict CSP
- [x] **Groups**: done in Phase 2.5 (see below)
- Done when: a non-developer can go from sign-up to sharing on the web. Verified directly in a browser: create org → create item → invite → confirm → share → remove (key rotation)

### Phase 2.5. Groups — Done

- [x] Group key pairs (X25519) and admin-signed group certificates. Clients wrap vault keys only for groups whose admin signature chains back to the pinned root
- [x] Share vaults with groups (view/edit/manage). When direct and group shares overlap, the stronger permission applies. The server uses the same rule to decide permissions
- [x] Adding a member hands over the current group key; removing a member **rotates the group key** and re-wraps the group's vault keys under the new group key. Admins who are not in the group open the group key through the recovery key copy
- [x] Group key copies are also wrapped with the recovery key. Account recovery restores group memberships as of the request, and suspension also removes group memberships
- [x] Admin console Groups tab, group selection in the share dialog, CLI `group` command, `vault create --group`, `vault share --group`
- Remaining risk: someone removed from a group may remember vault keys received before removal. Blocking later changes requires running **Rotate key** on that vault separately (the UI and CLI point this out)

### Phase 3. Browser extension (v1.0) — Done

- [x] Form detection: prefers autocomplete tokens and handles Korean labels (아이디, 비밀번호, 휴대폰, 인증번호: username, password, mobile phone, verification code), multi-step logins, shadow DOM, hidden decoy fields, and excluding search boxes
- [x] Inline menu: a key button inside the input and an extension-origin iframe menu, inside a closed shadow root. The menu receives only titles and usernames
- [x] eTLD+1 matching (handles the PSL, `co.kr`, `github.io`). https items are not filled on http pages
- [x] Single fill point: one-time menu tokens per tab. Right before filling, re-check that the tab is active and the frame URL is unchanged, and the content script re-checks `location.href` as well
- [x] Save/update prompts, TOTP code filling, generator, keyboard shortcut (`Ctrl/Cmd+Shift+L`, only when exactly one item matches)
- [x] Auto-lock: locks after 30 minutes of inactivity, when the OS locks, or when the browser restarts
- [x] Regression test suite: 12 login patterns common on Korean sites + shadow DOM
- [x] Real Chromium E2E: unlock in popup → fill from inline menu → fill OTP → save prompt
- [x] **Passkeys**: done in Phase 3.5 (see below)
- [x] Clipboard auto-clear for values copied from the extension: done in Phase 4.4
- [x] Firefox support: done in Phase 4.4
- Safari support: not done yet (Phase 4.5 covered only the desktop app)
- Done-when criterion (2 weeks of pilot use) still needs to be confirmed by running an internal pilot

### Phase 3.5. Passkeys — Done

- [x] ES256 authenticator in the SDK: `none` attestation, BE/BS flags (synced passkeys), signature counter 0. Registration and login cross-checked against an independent RP library (`@simplewebauthn/server`)
- [x] RP ID validation: only https (or localhost), and it must equal the origin host or be a registrable parent domain. Public suffixes (`co.kr`, `github.io`) and IPs are rejected. The origin comes only from `sender.url` as reported by the browser
- [x] Page interception (MAIN world) and consent window: choose where to save (existing or new item), pick a passkey, re-enter the password if needed (UV required), and fall back to the browser's built-in passkeys if declined
- [x] `excludeCredentials` (reject duplicate registration), `allowCredentials` (reject tampered selections), top frame only
- [x] Real Chromium E2E: on a test RP, register → log in → reject a wrong RP ID
- [x] Conditional UI (`mediation: "conditional"`, passkeys shown in the autofill list): done in Phase 4.4
- [x] Passkey import (FIDO CXF, `fido2Credentials` from Bitwarden exports): done in Phase 4.2. Export is not done yet

### Phase 4. After company-wide rollout

Phase 4 is split by purpose. The numbers give the order of work. Each phase targets one of the [success metrics](#success-metrics) above.

#### Phase 4.1. Access control: lock out leavers immediately — Done

Metric: time until access is cut off when someone leaves = immediate

- [x] Google Workspace SSO login: on top of the password and Secret Key check, requires verifying the company Google account (OIDC authorization code + PKCE, `hd` domain restriction, bound to the Google `sub` on first login). Turned on by org policy. Before turning it on, the admin's own login must pass SSO (so a misconfiguration can't lock everyone out)
- [x] When a Google account is suspended or deleted, the keymember session ends too: on every token refresh (15 minutes), the server re-checks the account with the stored Google refresh token. If Google refuses, the whole login is terminated; if Google is unreachable, there is a grace period of up to 1 hour after the last successful check
- [x] Unlock is still password + Secret Key. SSO is used only for identity verification ([ADR-007](decisions.md))
- [x] Offboarding: along with suspension, rotates the keys of the groups the person belonged to and the keys of vaults the acting admin manages. Other vaults are marked **Key rotation needed** and their admins are listed (web Members tab, CLI `member offboard`)
- Done when: suspending an account in Google Workspace makes keymember unusable on every device within the next token refresh (at most 15 minutes). Verified with a test OIDC provider (suspend → `sso_revoked` on the next refresh)
- Remaining risk: data already shown on an unlocked screen stays visible until the next API call. Confirming suspension against a real Google Workspace happens in the pilot after deployment

#### Phase 4.2. Eliminate plaintext sharing — Done

Metric: plaintext passwords left in Slack and Notion = 0

- [x] Share links: send people outside the vault (contractors, new hires before their start date) a snapshot of one item (title/URL + chosen fields) via a link limited by expiry (up to 30 days) and view count (1–100 views). The key lives only in the URL fragment, so the server cannot see it. Optional access password (mixed into the key with Argon2id), proof of access so only link holders can consume views, automatic revocation after 10 wrong passwords, automatic revocation of a person's links when they are offboarded, audit log. Web **Send as link**, CLI `item share`
- [x] Passkey import: `fido2Credentials` from Bitwarden exports (both GUID and `b64.` credential ids), FIDO CXF 1.x unencrypted JSON (logins, passkeys, TOTP, notes, collections). Only P-256 (ES256) keys are accepted; the rest are skipped with the reason shown. Verified by checking signatures made with imported keys against the original public keys
- Done when: we can tell people "don't send passwords over Slack, send a link". Verified on the web from creating a link → viewing it in a tab with no account (a wrong password doesn't consume a view; the link closes after one view)
- Remaining risk: the link itself is a secret. Sending the link and the password over the same channel defeats the password. Once the recipient opens it, keymember has no control over the values. CXF's encrypted transfer (CXP) is not supported yet

#### Phase 4.3. Security verification and hardening: safe to store real passwords — Internal work done, awaiting external review

Metric: "Implementation flaws in a self-built security product" in the risk table

- [x] Internal security review: reviewed four areas (server, crypto, extension, web/SSO) and fixed 5 High and a number of Medium/Low findings. Records and remaining risks are in [review-2026-10.md](../security/review-2026-10.md)
- [ ] External security review (carried over from Phase 0) and fixes for its findings. Materials for the reviewer are collected in the record above
- [x] Fuzzing (fast-check): CBOR, envelope, key wrapping, signature verification, 4 import parsers, PKCS#8, share links, TOTP, URL matching, extension message validators (differential), OIDC ID tokens. Found and fixed 2 bugs
- [x] The server no longer receives a login secret: Ed25519 signed challenges instead of OPAQUE ([ADR-003](decisions.md) updated). Existing accounts switch over at their next login
- [x] Post-quantum migration path: wrapping suite 2 is reserved for X-Wing, and the steps are written up in [pq-migration.md](pq-migration.md). The actual migration has not been done
- Done when: no findings of High or above remain from the review

#### Phase 4.4. Finishing the browser experience — Done except pilot items

Metric: autofill success rate on major sites of 95% or more

- [x] Clipboard auto-clear for values copied from the extension: after 30 seconds, cleared only if the value is still on the clipboard (hash comparison). Also cleared on lock. Chrome uses an offscreen document, Firefox the background page. Verified with real Chromium E2E
- [x] Passkey conditional UI (`mediation: "conditional"`): if keymember has a passkey for the site, **Sign in with passkey** appears at the top of the inline menu. If locked, if there is no matching passkey, or if the site requires user verification (UV required), it hands off to the browser. Verified with real Chromium E2E (RP validation passed)
- [x] Firefox build (`apps/extension/dist-firefox`): event page background, add-on id, Firefox 142 or later. Mozilla web-ext lint runs in CI (0 errors). **Behavior in real Firefox needs manual checking** (Playwright cannot load Firefox extensions)
- [ ] Add sites that fail in the pilot to the regression test suite: may require starting the pilot

#### Phase 4.5. Native apps — Desktop done, mobile on hold

- [x] Desktop app (`apps/desktop`, Electron, macOS first):
  - The main process holds the session; the window (sandbox, context isolation) sends only validated requests. Passwords and private keys never reach the window (the main process puts them on the clipboard itself and clears them after 30 seconds)
  - Touch ID unlock: when turned on after unlocking with the password, the session snapshot is sealed with the keychain (`safeStorage`) and opened with Touch ID. The password is required every 2 weeks, and the snapshot is deleted if the server has ended that login
  - SSH agent (OpenSSH agent protocol, Unix socket 0600): serves the vault's `ssh-key` items (Ed25519/ECDSA/RSA, OpenSSH/PEM) and asks for approval in the window on every signature (**Allow until locked** is available). Ed25519 key generation and import in the app
  - Locks on screen lock, sleep, or 10 minutes idle
  - Verification: unit tests checked against real `ssh-keygen`/`ssh-add` (7 key formats, signature verification), and E2E that launches real Electron with Playwright (unlock → copy → generate SSH key → `ssh-add -L` → approve signing → `ssh-keygen -Y verify`)
  - Installation: built from source instead of a distributed package (`pnpm desktop:install`, installed to `~/Applications`). A locally built app is not subject to Gatekeeper quarantine, so it opens without an Apple account. pnpm (`useNodeVersion`) pins the Node version. The package uses Electron fuses to disable Node mode, the inspector and `NODE_OPTIONS`, checks `app.asar` integrity, and loads the window from `app://keymember` instead of `file://`. macOS CI launches the built app to check it
  - Not doing: signed and notarized packages and auto-update (these need an Apple Developer account)
  - Not yet built: Windows (Windows Hello, named pipe agent), full vault management (use the web vault)
- On hold: mobile apps and OS autofill (iOS AutoFill, Android Autofill). Not currently planned (decided 2026-10-23)

#### Deployment — each company chooses (2026-10-24)

- Goal: a small company can run it for free without server operations know-how. keymember does not run a shared public server
- [x] The server handles storage only through `Store`. PostgreSQL/PGlite (`SqlStore`) and Firestore (`FirestoreStore`) use the same routes
- [x] Cloud Run + Firestore: runs on nothing but the company's Google Cloud project. Most team sizes stay within the free tier. [cloud-run.md](../deploy/cloud-run.md)
- [x] Docker + PGlite: a single `docker compose` on your own server, HTTPS included. [self-hosted.md](../deploy/self-hosted.md)
- [x] The full server test suite also runs against the Firestore emulator (CI). The deployment image is also built and started in CI
- Remaining: deploy once to a real Google Cloud project to confirm (the emulator does not check permissions or indexes)

#### Scope — default and optional components (2026-10-25)

- Default: the server (including the web vault and admin screens) and the browser extension. Most team members install only the extension
- Optional: the desktop app (Touch ID, SSH agent) and the CLI (`run`, import, scripting). Only for those who need them
- [x] `pnpm install` does not download the Electron binary, and `pnpm build` does not build the desktop app. For the desktop app, `pnpm desktop:install` downloads what it needs and builds it

#### Invite links — sign up without fingerprint comparison (2026-10-25)

- [x] When an admin enters an email address, an invite link is created and sent through a mail app (new message) or Slack (copy the message, then open the app). The server does not send email
- [x] The invitee opens the link and enters only a name and password. The owner key is pinned from the link
- [x] When the inviting admin's app (web, extension, desktop, CLI `members`) opens, it automatically confirms members who signed up through the link
- [x] The account's other devices receive the signed root stored with the account and skip fingerprint verification
- Design and remaining risks: [ADR-010](decisions.md)

### Remaining work (as of 2026-10-26)

| Item | Status |
|---|---|
| Confirm a Cloud Run + Firestore deployment on a real Google Cloud project | After the external security review (decided 2026-10-26) |
| External security review and fixes for its findings (Phase 4.3) | Waiting to engage a reviewer |
| First release tag `v0.1.0` (GHCR image release) | After the external security review (decided 2026-10-26) |
| Add sites that fail in the pilot to the regression tests (Phase 4.4) | Waiting for the pilot to start |
| Safari extension | Not doing |
| Windows support for the desktop app | Not doing |
| CPace-based new device linking | Not doing |
| Passkey export (FIDO CXF) | Not doing |
| Mobile apps and OS autofill | On hold |

## Success metrics

| Metric | Target |
|---|---|
| Company-wide sign-up rate after the pilot | 100% (enforced by policy) |
| Plaintext passwords left in Slack and Notion | 0 (via a campaign) |
| Autofill success rate on major sites | 95% or more (measured on the regression test suite) |
| Time until access is cut off when someone leaves | Immediate (one click in the admin console) |

## Risks

| Risk | Mitigation |
|---|---|
| **Implementation flaws in a self-built security product** | External review, audited libraries only, test vectors, fuzzing |
| Autofill quality falls short of commercial products | Regression test suite, feedback gathered in the pilot |
| Losing maintainers | Documented design, minimal code size |
| Support burden from lost Secret Keys | Emergency Kit storage on the onboarding checklist, plus admin recovery |

> Note: compared with commercial products (1Password Business at roughly KRW 4 million a year, Bitwarden Teams at roughly KRW 2 million a year), the value of this project lies in **control and learning rather than cost savings**. Whether to continue will be reassessed at the end of Phase 1.
