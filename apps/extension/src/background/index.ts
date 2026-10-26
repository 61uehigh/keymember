import { describeError } from "@keymember/client";
import { generatePassword } from "@keymember/core";

import type {
  ContentRequest,
  MenuRequest,
  PopupRequest,
} from "../shared/messages.js";
import { Autofill } from "./Autofill.js";
import { CLIPBOARD_ALARM, ClipboardGuard } from "./ClipboardGuard.js";
import { PasskeyBroker } from "./PasskeyBroker.js";
import { PasskeyStore } from "./PasskeyStore.js";
import { SavePrompts } from "./SavePrompts.js";
import { routeMessage } from "./senders.js";
import type { RoutedMessage } from "./senders.js";
import { Vault } from "./Vault.js";
import type { FillTarget } from "./Vault.js";

const IDLE_LOCK_MS = 30 * 60_000;
// The background's parts, each with one concern; the vault owns the session they share
const vault = new Vault();
const autofill = new Autofill(vault);
const savePrompts = new SavePrompts(vault);
const passkeys = new PasskeyBroker(vault, new PasskeyStore(vault, autofill));
const clipboard = new ClipboardGuard();

// However the vault locks, a copied secret comes off the clipboard right away
vault.onLock(async () => {
  await clipboard.clearIfUnchanged();
});

/**
 * ### activeTabFrames
 *
 * Frames of the active tab, as fill targets.
 *
 * @returns Every http(s) frame of the active tab
 */
async function activeTabFrames(): Promise<Array<FillTarget>> {
  const [tab] = await chrome.tabs.query({
    active: true,
    lastFocusedWindow: true,
  });

  if (tab?.id === undefined) {
    return [];
  }

  const tabId = tab.id;
  const frames = (await chrome.webNavigation.getAllFrames({ tabId })) ?? [];
  const top = frames.find((frame) => frame.frameId === 0);

  if (top === undefined || !/^https?:\/\//.test(top.url)) {
    return [];
  }

  const topOrigin = new URL(top.url).origin;

  // Credentials go to the page itself and its same-origin frames, never to embedded third parties
  return frames
    .filter(
      (frame) =>
        frame.frameId === 0 ||
        (/^https?:\/\//.test(frame.url) &&
          new URL(frame.url).origin === topOrigin),
    )
    .sort((a, b) => a.frameId - b.frameId)
    .map((frame) => ({ tabId, frameId: frame.frameId, url: frame.url }));
}

/**
 * ### dispatch
 *
 * Hands a routed message to the part that serves it.
 *
 * @param routed Message a sender was allowed to send
 * @returns The response
 */
async function dispatch(routed: RoutedMessage): Promise<unknown> {
  switch (routed.to) {
    case "popup":
      return handlePopup(routed.request);
    case "passkey-window":
      if (routed.request.type === "passkey-request") {
        return passkeys.view(routed.request.id);
      }

      passkeys.decide(routed.request.id, routed.request.decision);

      return {};
    case "menu":
      return handleMenu(routed.request, routed.tabId);
    case "content":
      return handleContent(routed.request, routed.target);
    case "passkey":
      return routed.allowed
        ? passkeys.handle(routed.request, routed.url, routed.tabId)
        : { outcome: "fallback" };
    case "passkey-conditional":
      return routed.allowed
        ? passkeys.registerConditional(routed.request, routed.url, routed.tabId)
        : { outcome: "fallback" };
  }
}

/**
 * ### handlePopup
 *
 * Serves the popup.
 *
 * @param request Validated popup request
 * @returns The response
 */
async function handlePopup(request: PopupRequest): Promise<unknown> {
  await vault.touch();

  switch (request.type) {
    case "state":
      return vault.state();
    case "configure":
      await vault.configure(request.serverUrl);

      return vault.state();
    case "unlock":
      return vault.unlock(request);
    case "owner-candidates":
      return vault.ownerCandidates();
    case "pin-owner":
      await vault.pinOwner(request.userId, request.fingerprint);

      return vault.state();
    case "lock":
      await vault.lock();

      return vault.state();
    case "copied":
      await clipboard.copied(request.value);

      return {};
    case "forget-device":
      await vault.forgetDevice();

      return vault.state();
    case "matches": {
      const [top] = await activeTabFrames();

      return top === undefined ? [] : autofill.rowsFor(top.url);
    }
    case "search":
      return autofill.search(request.query);
    case "reveal":
      return { value: await autofill.reveal(request.itemId, request.field) };
    case "fill":
      return {
        filled: await autofill.fill(request.itemId, await activeTabFrames()),
      };
    case "pending":
      return savePrompts.pending();
    case "save-pending":
      await savePrompts.savePending(request.id, request.vaultId);

      return savePrompts.pending();
    case "dismiss-pending":
      await savePrompts.dismissPending(request.id);

      return savePrompts.pending();
    case "generate":
      return {
        password: generatePassword({
          length: request.length,
          symbols: request.symbols,
        }),
      };
  }
}

/**
 * ### handleContent
 *
 * Serves content scripts. The frame URL always comes from the sender, never the message.
 *
 * @param request Validated content request
 * @param target Frame the request came from
 * @returns The response
 */
async function handleContent(
  request: ContentRequest,
  target: FillTarget,
): Promise<unknown> {
  switch (request.type) {
    case "menu-open":
      return { token: await autofill.issueMenuToken(target, request.kind) };
    case "save-candidate": {
      const prompt = await savePrompts.addPending(
        target,
        request.username,
        request.password,
      );

      if (prompt) {
        await chrome.action.setBadgeText({ tabId: target.tabId, text: "+" });
        await chrome.action.setBadgeBackgroundColor({
          tabId: target.tabId,
          color: "#2f5bea",
        });
      }

      return { prompt };
    }
  }
}

/**
 * ### handleMenu
 *
 * Serves the inline menu. Every request must carry a live token issued to the same tab.
 *
 * @param request Validated menu request
 * @param senderTabId Tab hosting the menu iframe
 * @returns The response
 */
async function handleMenu(
  request: MenuRequest,
  senderTabId: number | undefined,
): Promise<unknown> {
  const grant = await autofill.menuToken(request.token, senderTabId);

  if (grant === undefined) {
    return { error: "expired" };
  }

  switch (request.type) {
    case "menu-items": {
      const state = await vault.state();

      return state.user === undefined
        ? { locked: true, items: [], passkeys: [] }
        : {
            locked: false,
            items: await autofill.rowsFor(grant.url, grant.kind),
            passkeys: await passkeys.conditionalPasskeys(
              grant.tabId,
              grant.frameId,
              grant.url,
            ),
          };
    }
    case "menu-fill": {
      const tab = await chrome.tabs.get(grant.tabId);

      // A fill only goes to the tab the user is looking at
      if (!tab.active) {
        return { filled: 0 };
      }

      const filled = await autofill.fill(request.itemId, [grant], grant.kind);

      await autofill.consumeMenuToken(request.token);

      return { filled };
    }
    case "menu-passkey": {
      const tab = await chrome.tabs.get(grant.tabId);
      const frame = await chrome.webNavigation.getFrame({
        tabId: grant.tabId,
        frameId: 0,
      });

      // Same rule as filling: only the tab in front, and only the page the menu was opened on
      if (!tab.active || grant.frameId !== 0 || frame?.url !== grant.url) {
        return { signed: false };
      }

      const signed = await passkeys.completeConditional(
        grant.tabId,
        frame.url,
        request.itemId,
        request.credentialId,
      );

      await autofill.consumeMenuToken(request.token);

      return { signed };
    }
    case "menu-close":
      await chrome.tabs
        .sendMessage(
          grant.tabId,
          { type: "close-menu" },
          { frameId: grant.frameId },
        )
        // The page may have navigated away, taking the menu with it; then there is nothing to close
        .catch(() => undefined);

      return {};
  }
}

chrome.runtime.onMessage.addListener((message: unknown, sender, respond) => {
  const routed = routeMessage(message, sender, chrome.runtime.id);

  if (routed === undefined) {
    return false;
  }

  dispatch(routed).then(respond, (error: unknown) => {
    // Server errors arrive as codes; the popup and windows show them in Korean
    respond({ error: describeError(error) });
  });

  // Keeps the message channel open for the asynchronous response
  return true;
});

chrome.commands.onCommand.addListener((command) => {
  if (command !== "fill-login") {
    return;
  }

  void (async () => {
    const frames = await activeTabFrames();
    const [top] = frames;

    if (top === undefined) {
      return;
    }

    const rows = (await autofill.rowsFor(top.url)).filter(
      (row) => !row.insecure,
    );
    const [best] = rows;

    // Only fill without asking when exactly one login fits; otherwise the popup must decide
    if (best !== undefined && rows.length === 1) {
      await autofill.fill(best.id, frames);
    }
  })();
});

chrome.tabs.onUpdated.addListener((tabId, change) => {
  // A page that navigates away is no longer waiting for an autofill sign-in
  if (change.status === "loading") {
    void passkeys.forgetConditional(tabId);
  }

  // A login usually navigates right after submitting, so the badge is (re)applied once the new page is loaded
  if (change.status === "complete") {
    void savePrompts
      .hasPending(tabId)
      .then((pending) =>
        chrome.action.setBadgeText({ tabId, text: pending ? "+" : "" }),
      );
  }
});

chrome.windows.onRemoved.addListener((windowId) => {
  passkeys.windowClosed(windowId);
});

chrome.idle.onStateChanged.addListener((state) => {
  if (state === "locked") {
    void vault.lock();
  }
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === "auto-lock") {
    void vault.lockIfIdle(IDLE_LOCK_MS);
    void savePrompts.prune();
  } else if (alarm.name === CLIPBOARD_ALARM) {
    // Nothing to report to: an alarm has no caller, and the next copy or lock tries again
    void clipboard.clearIfUnchanged().catch(() => undefined);
  }
});

void chrome.alarms.create("auto-lock", { periodInMinutes: 1 });
