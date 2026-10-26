# Security policy

keymember stores a team's passwords, so a vulnerability report is worth more to us than any other
contribution. Thank you for taking the time.

## Reporting a vulnerability

**Do not open a public issue, discussion or pull request for a security problem.** Report it
privately instead:

- GitHub: use **Report a vulnerability** on the repository's Security tab (private vulnerability
  reporting), or
- Email: 61uehigh@gmail.com with the subject `keymember security`.

Please include what you found, how to reproduce it, which version or commit you tested, and the
impact you expect. Proofs of concept are welcome; please do not test against servers you do not
own, and never access other people's data.

## What to expect

- An acknowledgement within 3 working days.
- An initial assessment within 7 days, including whether we consider it a vulnerability.
- A fix, or a plan with a timeline, for confirmed issues. Critical issues are fixed first.
- Credit in the release notes and the advisory, unless you prefer to stay anonymous.

We ask you to keep the details private until a fix is released, or 90 days have passed,
whichever comes first.

## Supported versions

keymember is in its pilot stage and has not yet had an external security review. Only the
latest release receives security fixes. Self-hosters should follow releases and update promptly.

## Scope

In scope: the cryptography and protocol (`packages/core`, `packages/client`), the server
(`apps/server`), the web vault, the browser extension, the desktop app and the CLI, and the
deployment files in this repository.

Out of scope: attacks that need a fully compromised user device, social engineering, denial of
service by sheer volume, and findings in third-party services (Google Cloud, GitHub). The
documented residual risks in [docs/design/threat-model.md](docs/design/threat-model.md) are known;
reports that show they are worse than documented are in scope.
