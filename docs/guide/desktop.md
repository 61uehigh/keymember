# Desktop app (macOS, optional)

Provides quick search and copy, Touch ID unlock and an SSH agent. Vault management and sharing happen in the web vault.

## Install

There's no distributable package; you build and install it directly from source. An app you build on your own Mac isn't downloaded from the internet, so it opens without Apple signing or notarization. All you need is git and pnpm (pnpm fetches the right Node version itself).

```bash
brew install pnpm
git clone https://github.com/61uehigh/keymember.git
cd keymember
pnpm install
pnpm desktop:install
```

The app is installed to `~/Applications/keymember.app`. During development, run it without installing via `pnpm --filter @keymember/desktop start`.

## Update

Quit the app and run `git pull && pnpm install && pnpm desktop:install`. The first time you open it after an update, macOS asks once whether to let keymember use its keychain items, because the rebuilt app has a different signature. If you don't allow it, just enter your Secret Key again; you'll need to turn Touch ID unlock back on.

## SSH agent

Add the lines shown in the app's **SSH keys** tab to `~/.ssh/config`. Whenever ssh or git uses an SSH key from your vault, the app window asks you to allow it. You can generate a new key in the app (Ed25519) or import a private key that has no passphrase.
