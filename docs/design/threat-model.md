# Threat model

> Status: **Draft (needs review)**

## Assets

1. **Item contents**: passwords, TOTP seeds, passkeys, notes, attachments
2. **Item metadata**: which services someone uses (URLs, titles)
3. **Keys**: Account Key, vault keys, item keys, private keys
4. **Account control**: someone else logging in or changing sharing permissions

## Attackers and mitigations

| # | Attacker | Capability | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | **Attacker who leaked the server DB or a backup** | Can read the entire DB | E2EE. The Secret Key (2SKD) makes offline cracking impossible | Emails, names and org structure are exposed |
| T2 | **Malicious server, or attacker in control of the server** | Can tamper with responses and substitute public keys | Admin-signed public keys, AAD binding ciphertext to its context, hardcoded KDF floor, signed security state version, signed key grants, invites and recovery requests, signed-challenge login | Withholding data from shared vaults (availability), substituting the web vault JS (T6), collusion with a certified member, rollback to old certificates or generations ([review notes](../security/review-2026-10.md)) |
| T3 | **Network attacker** | Can observe or tamper outside TLS | TLS 1.3 and HSTS. Data is already E2EE | AUTH may be exposed at the TLS termination point (ADR-003). Mitigated by 2FA |
| T4 | **Former employee or member whose access was revoked** | May remember keys received earlier | The server stops delivering data and rotates the vault key. With the SSO policy on, suspending the Google account cuts off login on every device within 15 minutes, and offboarding immediately rotates group keys and the vault keys the admin manages, then asks admins to rotate the remaining vaults | **Items received before rotation** are already exposed. Handled with a checklist for changing the affected passwords. Leaving a group rotates the group key, but a vault key only changes when that vault's key is rotated |
| T5 | **Admin abusing their privileges** | Can misuse the recovery feature | Two-person approval (requester and approver must both have been certified members for at least 7 days, so one admin cannot approve with a freshly created second identity), the recovery request signs the key version to be replaced and the admin completing recovery re-wraps only to the next key version, notification to the target user, automatic cancellation on login with the existing password, audit log and Slack alerts | Two colluding admins; an admin opening group vaults through the recovery key copy |
| T6 | **Attacker who substitutes the web vault code** | Can ship malicious JS to the browser | Strict CSP (`script-src 'self'`, no inline scripts, `frame-ancestors 'none'`) and `no-store`. Day-to-day use is steered to the extension and CLI | An inherent limit of web clients (1Password A.1). The web vault remembers the Secret Key in `localStorage`, so XSS would expose it. The password is still required |
| T7 | **Phishing site** | Tries to collect credentials on a lookalike domain | eTLD+1 matching, confirmation before autofill, no autofill on page load, warning for untrusted iframes | Users copying and pasting credentials themselves |
| T8 | **Malware on the device** | Can see memory and keystrokes | **Cannot be prevented.** Auto-lock, OS secure storage and automatic clipboard clearing only shorten the exposure window | All data while unlocked |
| T9 | **Malicious browser extension** | Can read the DOM | The autofill menu is shown in an isolated iframe | Values already filled in can be read |
| T12 | **Someone who intercepts a share link** | Obtains the link (and the view password) | Expiry and view-count limits, per-link view password (sent over a different channel), revocation after 10 wrong passwords, revocation by the sender or an admin, automatic revocation on offboarding. The server cannot see the content without the link | Cannot help if the link and password travel over the same channel, or if they are intercepted before the recipient opens them. No control over the values once the recipient opens them |
| T11 | **Site trying to capture passkeys** | Registers or requests login with another site's RP ID | The RP ID is validated against the origin reported by the browser (public suffixes and IPs are rejected). Only the top-level frame is allowed, and a stored passkey signs only for its own RP ID | A user approving the wrong site in the consent window. The window shows the origin |
| T13 | **Local program running as the same user (desktop app)** | Requests signatures from the SSH agent socket and tries to read the app's keychain entries | The agent socket is user-only (0600), and each signature needs approval in a window (can be remembered until lock). The Touch ID snapshot is sealed with the keychain, and the password is required every 2 weeks | Electron `safeStorage` keychain entries are not hardware-protected by Touch ID. Malware running as the same user can open the snapshot with the keychain key (same category as T8). A key allowed with **Allow until locked** can also be used by other processes in the meantime. The app is built from source by the user and only ad-hoc signed, so its authenticity rests on the repository the user obtained (GitHub over HTTPS) and the locked dependencies (lockfile integrity hashes). The keychain asks for access again after every update, which trains users to approve the prompt by habit |
| T10 | **Stolen device** | Has access to the disk | The local cache is E2EE, and the PIN lock wipes after 5 failed attempts. Devices can be deauthorized remotely | A weak password can be cracked together with the Secret Key |

## Out of scope

- **A compromised operating system or browser** (T8)
- **A user leaking both the Emergency Kit and the password**
- **Availability attacks (DoS)**: Low priority for an internal service of about 30 people
- **Quantum computers**: We only make sure the HPKE suite ID allows a swap

## Trust boundaries

Which tier enforces each control follows the three tiers described by 1Password.

| Control | Tier |
|---|---|
| Decryption, sharing, public key trust | Cryptographic |
| Edit permissions, data delivery, recovery approval, policies | Server |
| Password hiding, export blocking, print blocking | **Client only**. Can be bypassed |

When configuring a control that is enforced only on the client, the admin console UI marks it as **"not a security boundary"**.
