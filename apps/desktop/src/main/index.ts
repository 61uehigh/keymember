import { mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";

import {
  app,
  BrowserWindow,
  clipboard,
  ipcMain,
  powerMonitor,
  protocol,
  safeStorage,
  shell,
  systemPreferences,
} from "electron";

import { describeError } from "@keymember/client";

import {
  IPC_CHANNEL,
  SIGN_ANSWER_CHANNEL,
  SIGN_REQUEST_CHANNEL,
  STATE_CHANGED_CHANNEL,
} from "../shared/channels.js";
import { desktopRequestSchema, signAnswerSchema } from "../shared/ipc.js";
import type {
  AgentInfo,
  DesktopRequest,
  SignRequestView,
} from "../shared/ipc.js";
import { createDesktopVault } from "./createDesktopVault.js";
import type { DesktopVault } from "./DesktopVault.js";
import type { PlatformServices } from "./platform.js";
import { SshAgent } from "./ssh/SshAgent.js";

const IDLE_LOCK_SECONDS = 10 * 60;
const SIGN_PROMPT_TIMEOUT_MS = 60_000;
// The longest quitting waits for a Touch ID reseal and the clipboard to finish
const QUIT_WAIT_MS = 3_000;

if (!app.requestSingleInstanceLock()) {
  app.quit();
}

protocol.registerSchemesAsPrivileged([
  { scheme: "app", privileges: { standard: true, secure: true } },
]);

const dataDir = app.getPath("userData");
const socketPath = join(dataDir, "agent.sock");
// The window's files come from a private app:// origin rather than file://, so the page cannot
// reach other local files and the packaged app keeps file:// without extra privileges
const APP_ORIGIN = "app://keymember";
const indexUrl = `${APP_ORIGIN}/index.html`;
const pageFiles: Readonly<Record<string, string>> = {
  "/index.html": "text/html; charset=utf-8",
  "/renderer.js": "text/javascript; charset=utf-8",
  "/styles.css": "text/css; charset=utf-8",
};
const pendingSigns = new Map<
  string,
  (answer: "session" | "once" | "deny") => void
>();
let window: BrowserWindow | undefined;
let agentError: string | undefined;

/**
 * ### secretBox
 *
 * Keychain-backed encryption, or `undefined` where the OS offers nothing real (Linux without a
 * keyring falls back to a fixed key, which is no protection).
 *
 * On macOS the Keychain is always there, and asking whether encryption is available already
 * reads the Keychain item. A rebuilt app has a new signature, so that read waits on macOS's
 * "allow access" prompt; done at startup it would hold the app before any window shows. The
 * Keychain is therefore first touched when the vault needs it, and a refusal makes
 * `encrypt`/`decrypt` throw, which the vault handles.
 *
 * @returns The secret box
 */
function secretBox(): PlatformServices["secretBox"] {
  if (
    process.platform !== "darwin" &&
    (!safeStorage.isEncryptionAvailable() ||
      (process.platform === "linux" &&
        safeStorage.getSelectedStorageBackend() === "basic_text"))
  ) {
    return undefined;
  }

  return {
    encrypt: (plaintext) =>
      new Uint8Array(safeStorage.encryptString(plaintext)),
    decrypt: (ciphertext) => safeStorage.decryptString(Buffer.from(ciphertext)),
  };
}

/**
 * ### showWindow
 *
 * Shows the window, creating it if needed.
 *
 * @returns The window
 */
function showWindow(): BrowserWindow {
  if (window !== undefined && !window.isDestroyed()) {
    window.show();
    window.focus();

    return window;
  }

  const created = new BrowserWindow({
    width: 440,
    height: 680,
    minWidth: 380,
    minHeight: 520,
    title: "keymember",
    show: false,
    webPreferences: {
      preload: join(__dirname, "preload.cjs"),
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      webSecurity: true,
      spellcheck: false,
    },
  });

  // The window only ever shows the bundled page; links and pop-ups go nowhere
  created.webContents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  created.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  created.once("ready-to-show", () => {
    created.show();
  });
  void created.loadURL(indexUrl);
  window = created;

  return created;
}

/**
 * ### createVault
 *
 * Builds the vault with this computer's services. Called once the app is ready, since the
 * secret box and Touch ID can only be queried then.
 *
 * @returns The vault
 */
function createVault(): DesktopVault {
  return createDesktopVault({
    dataDir,
    secretBox: secretBox(),
    biometric:
      process.platform === "darwin" && systemPreferences.canPromptTouchID()
        ? (reason) =>
            systemPreferences.promptTouchID(reason).then(
              () => true,
              () => false,
            )
        : undefined,
    clipboard: {
      read: () => clipboard.readText(),
      write: (text) => {
        void clipboard.writeText(text);
      },
    },
    openExternal: (url) => {
      // Only identity-provider sign-in pages are opened, and only over http(s)
      if (/^https?:\/\//.test(url)) {
        void shell.openExternal(url);
      }
    },
    confirmSigning: (request) =>
      new Promise((resolve) => {
        const id = crypto.randomUUID();
        const timer = setTimeout(() => {
          pendingSigns.delete(id);
          resolve("deny");
        }, SIGN_PROMPT_TIMEOUT_MS);

        pendingSigns.set(id, (answer) => {
          clearTimeout(timer);
          pendingSigns.delete(id);
          resolve(answer);
        });
        showWindow().webContents.send(SIGN_REQUEST_CHANNEL, {
          id,
          ...request,
        } satisfies SignRequestView);
      }),
  });
}

/**
 * ### handle
 *
 * Carries out one validated request from the window.
 *
 * @param vault The vault
 * @param request Request
 * @returns The answer
 */
async function handle(
  vault: DesktopVault,
  request: DesktopRequest,
): Promise<unknown> {
  switch (request.type) {
    case "state":
      return vault.state();
    case "configure":
      await vault.configure(request.serverUrl);

      return vault.state();
    case "unlock":
      return vault.unlock(request);
    case "unlock-biometric":
      return vault.unlockWithBiometric();
    case "set-biometric":
      await vault.setBiometric(request.enabled);

      return vault.state();
    case "lock":
      await vault.lock();

      return vault.state();
    case "owner-candidates":
      return vault.ownerCandidates();
    case "pin-owner":
      await vault.pinOwner(request.userId, request.fingerprint);

      return vault.state();
    case "search":
      return vault.search(request.query);
    case "copy":
      vault.copy(request.itemId, request.field);

      return {};
    case "ssh-keys":
      return vault.keyring.list();
    case "writable-vaults":
      return vault.writableVaults();
    case "add-ssh-key":
      return { id: await vault.addSshKey(request) };
    case "agent-info":
      return {
        socketPath,
        ...(agentError === undefined ? {} : { error: agentError }),
      } satisfies AgentInfo;
  }
}

void app.whenReady().then(async () => {
  // Serves only the bundled page's own files
  protocol.handle("app", async (request) => {
    const url = new URL(request.url);
    const type = pageFiles[url.pathname];

    // URL gives non-special schemes a "null" origin, so compare the parts
    if (
      url.protocol !== "app:" ||
      url.host !== "keymember" ||
      type === undefined
    ) {
      return new Response(null, { status: 404 });
    }

    return new Response(await readFile(join(__dirname, url.pathname)), {
      headers: { "content-type": type },
    });
  });
  await mkdir(dataDir, { recursive: true });

  const vault = createVault();
  const agent = new SshAgent(vault.keyring);

  ipcMain.handle(IPC_CHANNEL, async (event, message: unknown) => {
    // Only the bundled page may talk to the vault
    if (event.senderFrame?.url !== indexUrl) {
      throw new Error("Unexpected sender");
    }

    const request = desktopRequestSchema.safeParse(message);

    if (!request.success) {
      throw new Error("Malformed request");
    }

    try {
      return await handle(vault, request.data);
    } catch (error) {
      // The window shows this text; server errors become the same Korean messages as elsewhere
      throw new Error(describeError(error), { cause: error });
    }
  });
  vault.onLocked(() => {
    if (window !== undefined && !window.isDestroyed()) {
      window.webContents.send(STATE_CHANGED_CHANNEL);
    }
  });
  ipcMain.on(SIGN_ANSWER_CHANNEL, (event, message: unknown) => {
    const answer = signAnswerSchema.safeParse(message);

    if (event.senderFrame?.url === indexUrl && answer.success) {
      pendingSigns.get(answer.data.id)?.(answer.data.answer);
    }
  });

  // Locking follows the computer: screen lock, sleep, or ten idle minutes
  powerMonitor.on("lock-screen", () => {
    void vault.lock();
  });
  powerMonitor.on("suspend", () => {
    void vault.lock();
  });

  setInterval(() => {
    if (powerMonitor.getSystemIdleTime() >= IDLE_LOCK_SECONDS) {
      void vault.lock();
    }
  }, 30_000);

  let quitting = false;

  app.on("will-quit", (event) => {
    if (quitting) {
      return;
    }

    // Quit after a pending Touch ID reseal is written and a copied secret is cleared, but never
    // wait long. The SSH agent's open connections are only closed, not waited for
    event.preventDefault();
    quitting = true;
    void agent.close();
    void Promise.race([
      vault.settle(),
      new Promise((resolve) => setTimeout(resolve, QUIT_WAIT_MS)),
    ])
      .catch((error: unknown) => {
        console.warn("keymember: finishing before quit failed", error);
      })
      .finally(() => {
        // The quit already ran its events; exit without starting it again
        app.exit(0);
      });
  });

  try {
    await agent.listen(socketPath);
  } catch (error) {
    // The vault stays usable without SSH; the SSH tab says why the agent is missing
    agentError = error instanceof Error ? error.message : String(error);
  }

  showWindow();
});

app.on("second-instance", () => {
  showWindow();
});

app.on("activate", () => {
  showWindow();
});

// The SSH agent keeps serving with the window closed on macOS, like other menu-bar-less apps
app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});
