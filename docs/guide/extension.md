# Browser extension

## Install

1. Run `pnpm build`. The extension is built into `apps/extension/dist`.
2. In Chrome, open `chrome://extensions` and turn on Developer mode.
3. Click "Load unpacked" and select `apps/extension/dist`.
4. Click the keymember icon in the toolbar, enter the server URL and unlock. The first time, you'll need your Secret Key.

In Firefox (142 or later), go to `about:debugging#/runtime/this-firefox`, click "Load Temporary Add-on" and open `apps/extension/dist-firefox/manifest.json`. The Firefox build is only checked automatically with the Mozilla linter, so please verify that it actually works yourself.

## Usage

- **Fill**: Click a login field and a key button appears at its right edge. Click it to see the items that match this site, then pick one to fill it in. If only one item matches, you can also fill it with `Ctrl/Cmd+Shift+L`.
- **Passkeys**: When you create a passkey or log in with one, a keymember window pops up so you can choose where to save it or which passkey to use. If you decline, the browser's built-in passkey flow takes over. On sites that support passkey autofill, the keymember menu on the username field shows **Sign in with passkey**.
- **Clipboard**: Copied passwords and codes are cleared after 30 seconds. If you've copied something else in the meantime, it's left alone.
