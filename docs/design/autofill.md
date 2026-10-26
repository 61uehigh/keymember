# Browser extension and autofill design

> Status: **Draft (needs review)**
> Basis: [Bitwarden analysis §3](../analysis/bitwarden.md#3-browser-extension-and-autofill)

Autofill quality drives user satisfaction more than anything else in reviews. It is also the front line of phishing defense. So we adopt the defenses Bitwarden has built up over the years as they are, while avoiding its sprawling file structure.

## 1. Structure (MV3)

```
[Static content script: only signals; all frames, document_start]
        │ "inject me"
        ▼
[service worker] ──chrome.scripting──► [Autofill content script (isolated world)]
   │  - lock state, keys (storage.session)          │ collects forms → sends opid metadata only
   │  - matching, single commit point               ▼
   │                                      [Inline menu iframe: extension origin, closed shadow, top layer]
   └──── native messaging (pairing) ────► [Desktop app (later): biometrics]
```

**Principles**

1. **The background must be restartable with no in-memory state.** Designed from the start on the assumption that the service worker can be terminated at any time. All required state lives in `storage.session`.
2. **Send as few secrets as possible to content scripts and the menu.**
   - The menu receives only titles and usernames.
   - Values go to the frame only at the moment of filling.
3. **Filling happens in exactly one place (commit).** Right before committing, re-check that:
   - the tab is in the foreground
   - the URL has not changed
   - the frame origin matches
   - the frame is not sandboxed
4. **Keep modules under 1,000 lines.** Collection, classification, matching, filling, menu and notifications each get a separate package. Bitwarden's 3,000+ line files are the cautionary example.

## 2. Matching

| Method | Supported | Notes |
|---|---|---|
| **eTLD+1 (default)** | ✓ | Includes the PSL and private domains. Subdomains such as `github.io` and `vercel.app` are treated as distinct |
| Host (+port) | ✓ | |
| Exact origin | ✓ | Scheme, host and port must all match |
| StartsWith | ✗ | "Origin + path prefix" is supported instead |
| Regex | ✗ | ReDoS risk, and easy for users to get wrong |
| Equivalent domain groups | ✓ | **Defined and signed by org admins**. Used for things like the company's set of SSO domains |

## 3. Phishing and safeguards

- **No autofill on page load.** Fill only on explicit user action (menu click, keyboard shortcut, context menu).
- **Untrusted iframes** (origin differs from top): show a warning in extension UI. Never use `confirm()`.
- **HTTP pages**: warn when filling an item saved for HTTPS.
- **Input validation**: check `isTrusted` on every input to the menu.
- **Clickjacking defense**: check opacity and visibility along the menu's entire ancestor chain. Bitwarden only has a TODO for this. Also detect when the menu is covered by other elements.
- **Message channels**: messages are protected by a random per-tab port key and a pinned origin. Privileged commands verify `sender.id`, `sender.origin` and whether the sender is the top frame.

## 4. Form detection

- `autocomplete` tokens come first, then heuristics on type, name, id, label and placeholder.
- The keyword dictionary is **kept in separate data files**. It includes Korean keywords: 아이디 (username), 비밀번호 (password), 휴대폰 (mobile phone), 인증번호 (verification code), etc.
- Also handle:
  - shadow DOM (including closed)
  - shadow roots attached late
  - lazy rendering (IntersectionObserver)
  - multi-step logins (username → password)
- **Patterns common on Korean sites** are part of the test suite too: virtual keypads, iframe logins, multi-step authentication, etc. We state explicitly that virtual keypads cannot be filled.
- Tests: snapshot real login pages to build a regression test suite.

## 5. Save and update prompts

- After detecting a form submission (submit event, trusted click or Enter), ask whether to save once navigation completes.
- Pending credentials are kept **encrypted with a session key**, with a 60-second TTL. Bitwarden keeps them in plaintext for 150 seconds.
- Decision logic: classify the scenario by the combination of username, password and new-password fields (Bitwarden's `u/p/n` approach).

## 6. Passkeys

- Intercept `navigator.credentials` in the MAIN world. However, **the background determines the origin itself from `sender.origin`** and cross-checks it against the value reported by the content script.
- Supported algorithms: ES256 (required), EdDSA (optional).
- Every authentication requires user verification (UV) in extension UI.
- The signature counter is fixed at 0. This is the convention for products that sync passkeys, and the BE and BS flags are set accordingly.
- Keys are stored encrypted inside the item details. **One item can hold multiple passkeys.**

## 7. Locking and clipboard

- Keys live only in `storage.session`. **There is no option to keep plaintext keys on disk ("never lock").**
- Decrypted vault cache: only overviews stay in memory. Details are decrypted on demand.
- Auto-lock triggers: idle time, OS lock (`idle.onStateChanged`), browser restart.
- Clipboard: cleared after 30 seconds. **A hash of the copied value is stored in `storage.session`**, and the clipboard is cleared only if the current value matches. This way it can still be cleared after a service worker restart.

## 8. TOTP and generator

- TOTP: RFC 6238 (SHA-1/256/512, 6–8 digits). Parses `otpauth://` URIs and scans QR codes. Also fills split OTP input boxes.
- Generator:
  - Characters: 20 characters by default. Option to exclude ambiguous characters. Random values are drawn uniformly from a CSPRNG.
  - Passphrase: EFF word list, 5 words by default.
  - Org policy can enforce a minimum length.

## 9. Implementation notes (Phase 3)

- **Injection**: the design says "a static script only signals; the real code is injected dynamically", but the actual content script is small enough at 8.6 KB that we started with a single static content script. It uses a hand-written validator instead of zod.
- **Session storage**: because the service worker can be terminated at any time, the unlocked session is snapshotted to `chrome.storage.session` (memory only, gone when the browser closes, not accessible from content scripts). The snapshot is updated whenever the refresh token rotates.
- **Sender verification**: the background checks `sender.id` on every message. Extension pages are distinguished by path (`/popup.html`, `/menu.html`). Because of `use_dynamic_url`, the menu iframe's host is a dynamic ID that changes per session. For content script messages, the page URL is read only from `sender.url`, never from the message body.
- **Menu tokens**: opening the menu issues a one-time token (2 minutes) bound to that tab, frame, URL and field type, passed to the iframe in the fragment. Tokens used from a different tab are rejected.
- **Not yet built**: autofill on page load (intentionally not offered). Clipboard auto-clear and passkeys were added in later phases, and in Phase 4.3 the clickjacking check moved to IntersectionObserver v2 (which also checks occlusion and opacity).

## 10. Passkey implementation notes (Phase 3.5)

- **Flow**:
  1. A page script (MAIN world, `document_start`) wraps `navigator.credentials.create/get`.
  2. The request passes through a bridge in the isolated world (`document_start`, top frame) to the background `PasskeyBroker`.
  3. The broker opens a consent window (`passkey.html`, an extension window) and waits for the user's decision.
- **Trust boundary**: the page script decides nothing, since the page can tamper with it. The origin comes from `sender.url`, and the background validates the RP ID. The consent window's choice is checked again too: picking a passkey outside the request's RP ID and `allowCredentials` is rejected.
- **User verification (UV)**: UV is set only if the password was entered while handling this request (changed in Phase 4.3). If the site requires `userVerification: "required"`, the consent window asks for the password.
- **Handed off to the browser**: sites that don't accept ES256, logins with no saved passkey, conditional UI that requires UV or has no matching passkey (§11), iframe requests, and when the user chooses "Use another device".
- **Storage**: the passkey private key (a P-256 scalar) lives inside the item details, so it is E2E encrypted like any other secret. The web vault shows passkeys read-only, and editing an item does not remove its passkeys.

## 11. Implementation notes (Phase 4.4)

- **Clipboard**: when the popup copies, the background keeps only the value's SHA-256 in session storage and sets a 30-second alarm. On the alarm (or on lock) it reads the clipboard and clears it only if the hash matches, leaving anything else the user copied in the meantime untouched. Chrome has no DOM in the service worker, so it briefly opens an offscreen document; Firefox handles it directly in the background page. Requires the `clipboardRead` permission.
- **Conditional UI**: the page's `navigator.credentials.get({ mediation: "conditional" })` is parked per tab in session storage (surviving service worker shutdowns), and that site's passkeys appear in the inline menu opened in a same-origin top frame. Choosing one signs and returns the result to the waiting page. It is discarded if the page cancels or the tab navigates. Picking from a list shows only user presence, so the UV flag is not set, and UV-required requests are handed to the browser.
- **Firefox**: the same source is built with an event page background. Differences and limitations:
  - There is no offscreen document, so the clipboard is handled in the background page (the offscreen code is dropped at build time).
  - `sender.origin` may be missing, so the frame URL's origin is used instead. In that case sandboxed pages (opaque origin) cannot be told apart.
  - There is no IntersectionObserver v2 (`trackVisibility`), so clickjacking defense for the inline button and menu weakens to checking only that it is on screen. The 500 ms delay and trusted-click check still apply.
  - There is no `use_dynamic_url`, but Firefox randomizes the extension address per install.
