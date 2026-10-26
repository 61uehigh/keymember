# Contributing

Thank you for helping. keymember is a password manager, so changes are reviewed with security in
mind first; please read [SECURITY.md](SECURITY.md) before reporting anything that could be a
vulnerability.

## Setup

You need git and [pnpm](https://pnpm.io) 10. pnpm downloads the Node version the workspace pins.

```bash
pnpm install
pnpm build
```

The guides in [docs/guide](docs/guide) explain how to run the server, web vault, extension, desktop
app and CLI locally.

## Before you open a pull request

```bash
pnpm check
```

This runs the type checks, ESLint, Prettier and the unit and integration tests. Changes to the
server should also pass the suite on Firestore:

```bash
PATH=/opt/homebrew/opt/openjdk@21/bin:$PATH pnpm firestore:emulator
pnpm test:firestore
```

Changes to the extension or the desktop app should pass the end-to-end tests (`pnpm test:e2e`).

## Conventions

- TypeScript, strict. Every exported symbol and its members carry a TSDoc block whose first line
  is `### <identifier>`. Comments and user-facing text are in English.
- Keep cryptographic changes small and separate, with tests and an update to
  [docs/design/crypto.md](docs/design/crypto.md). New signed statements get their own signature
  domain.
- Design decisions that change the security model get an entry in
  [docs/design/decisions.md](docs/design/decisions.md).
- Commit messages describe what changed and why, in the imperative mood.

## Licence

By contributing you agree that your contribution is licensed under the Apache License 2.0, the
licence of this repository.
