# Changelog

Notable changes per release. Releases are git tags (`vX.Y.Z`); self-hosters should deploy a tag,
not `main`. Database changes run automatically on start and cannot be undone, so back up before
upgrading.

## Unreleased

First public version, in its pilot stage: before an external security review.

- End-to-end encrypted vaults shared with members and groups, with signed member certificates
  and key grants, from a pinned owner key
- Web vault and admin console, browser extension (Chrome, Firefox), macOS desktop app, CLI
- Invite links that certify new members without a fingerprint comparison
- Two-admin account recovery, share links, company-account sign-in (OIDC), audit log
- Two deployments: Cloud Run with Firestore, or Docker with built-in PGlite behind Caddy
- Creating the organisation needs a one-time bootstrap token from the server log
  (or `KEYMEMBER_BOOTSTRAP_TOKEN`)

Upgrading from a pre-release checkout: group members added before group memberships were signed
count as unverified and are left out of the next group key rotation; add them again.
