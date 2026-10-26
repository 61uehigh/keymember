<p align="center"><img src="branding/icon.svg" alt="" width="96" height="96" /></p>

<h1 align="center">keymember</h1>

<p align="center"><b>Don't remember — keymember.</b><br />An end-to-end encrypted password manager for teams, run on your company's own infrastructure</p>

## Why keymember

Lightweight and free, with no compromise on security.

- #### Encryption even the server can't read

  Everything is encrypted on your device; the server stores only ciphertext. Even a compromised server can't read your data or slip in a fake key to intercept it.

- #### A key structure built for breaches

  Your password is combined with a 128-bit Secret Key, so even a full database leak can't be cracked offline.

- #### Light to self-host

  One container or one Cloud Run service runs it on your company's infrastructure. For a team, the cloud free tier is enough.

- #### Free for good

  Open source under Apache-2.0, so it costs nothing as your team grows.

- #### Built for teams

  Vault sharing, groups, invite links, account recovery approved by two admins, company-account SSO and offboarding.

## Getting started

1. **Run the server.** Choose [Cloud Run + Firestore](docs/deploy/cloud-run.md) or [your own server (Docker)](docs/deploy/self-hosted.md).
2. **Teammates install the [browser extension](docs/guide/extension.md).** For most people, that's all they need.
3. Use the [desktop app](docs/guide/desktop.md) (macOS) or the CLI if you want them.

To try it on your own machine before deploying, see [Try it locally](docs/guide/quickstart.md).

## Documentation

- Guides: [Try it locally](docs/guide/quickstart.md) · [Browser extension](docs/guide/extension.md) · [Desktop app](docs/guide/desktop.md) · [SSO and offboarding](docs/guide/sso.md)
- Design: [Cryptography](docs/design/crypto.md) · [Architecture](docs/design/architecture.md) · [Threat model](docs/design/threat-model.md) · [Design decisions](docs/design/decisions.md) · [Roadmap](docs/design/roadmap.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md) · Reporting security issues: [SECURITY.md](SECURITY.md)

## License

[Apache License 2.0](LICENSE)
