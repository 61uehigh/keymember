import { rpIdAllowed } from "@keymember/client";
import { fromBase64Url } from "@keymember/core";

import type {
  MenuPasskey,
  PasskeyConditionalRequest,
  PasskeyContentRequest,
  PasskeyDecision,
  PasskeyReply,
  PasskeyRequestView,
} from "../shared/messages.js";
import { ConditionalRequests } from "./passkeys/ConditionalRequests.js";
import { ConsentWindows } from "./passkeys/ConsentWindows.js";
import { assertionReply, PasskeyCeremony } from "./passkeys/PasskeyCeremony.js";
import { errorReply } from "./passkeys/replies.js";
import type { PasskeyStore } from "./PasskeyStore.js";
import type { Vault } from "./Vault.js";

/**
 * ### ES256
 *
 * COSE algorithm id of the only signature scheme keymember implements.
 */
const ES256 = -7;

/**
 * ### PasskeyBrokerParts
 *
 * The parts a broker coordinates; tests may hand in their own.
 */
export interface PasskeyBrokerParts {
  readonly windows: ConsentWindows;
  readonly conditional: ConditionalRequests;
  readonly ceremony: PasskeyCeremony;
}

/**
 * ### PasskeyBroker
 *
 * Handles passkey requests from pages: checks the relying party id against the origin the
 * browser reports, asks the user in a consent window ({@link ConsentWindows}), then creates or
 * signs with a passkey ({@link PasskeyCeremony}). Autofill sign-ins wait per tab in
 * {@link ConditionalRequests}. Requests keymember cannot or should not answer are handed back to
 * the browser.
 */
export class PasskeyBroker {
  readonly #vault: Pick<Vault, "state" | "unlockCount">;
  readonly #passkeys: Pick<
    PasskeyStore,
    "findPasskey" | "passkeyCandidates" | "passkeyTargets" | "writableVaults"
  >;
  readonly #windows: ConsentWindows;
  readonly #conditional: ConditionalRequests;
  readonly #ceremony: PasskeyCeremony;

  /**
   * ### constructor
   *
   * @param vault Lock state and how many times the user has unlocked
   * @param passkeys Stored passkeys
   * @param parts Consent windows, waiting autofill sign-ins and the ceremony; built from the
   * vault and passkeys when omitted
   */
  constructor(
    vault: Pick<Vault, "state" | "unlockCount">,
    passkeys: Pick<
      PasskeyStore,
      | "findPasskey"
      | "passkeyCandidates"
      | "passkeyTargets"
      | "storePasskey"
      | "writableVaults"
    >,
    parts: PasskeyBrokerParts = {
      windows: new ConsentWindows(),
      conditional: new ConditionalRequests(),
      ceremony: new PasskeyCeremony(vault, passkeys),
    },
  ) {
    this.#vault = vault;
    this.#passkeys = passkeys;
    this.#windows = parts.windows;
    this.#conditional = parts.conditional;
    this.#ceremony = parts.ceremony;
  }

  /**
   * ### handle
   *
   * Answers one `navigator.credentials` call from a top-level page.
   *
   * @param request Validated request from the content script
   * @param pageUrl URL of the requesting frame, from the browser
   * @param tabId Requesting tab, so each tab has at most one consent window open
   * @returns The reply for the page script
   */
  async handle(
    request: PasskeyContentRequest,
    pageUrl: string,
    tabId?: number,
  ): Promise<PasskeyReply> {
    const url = new URL(pageUrl);

    // A page cannot stack consent windows to wear the user down or line up a misclick
    if (tabId !== undefined && this.#windows.hasOpenFor(tabId)) {
      return errorReply(
        "NotAllowedError",
        "Another passkey request from this tab is still open.",
      );
    }
    const rpId =
      (request.type === "passkey-create"
        ? request.options.rp.id
        : request.options.rpId) ?? url.hostname;

    if (!rpIdAllowed(rpId, url.origin)) {
      return errorReply(
        "SecurityError",
        "The relying party id is not valid for this origin.",
      );
    }

    if (request.type === "passkey-create") {
      const params = request.options.pubKeyCredParams;

      // Only ES256 is implemented; let the browser serve sites that ask for anything else
      if (
        params.length > 0 &&
        !params.some(
          (param) => param.type === "public-key" && param.alg === ES256,
        )
      ) {
        return { outcome: "fallback" };
      }
    } else if ((await this.#vault.state()).user !== undefined) {
      const allow = request.options.allowCredentials.map((entry) => entry.id);

      if ((await this.#passkeys.passkeyCandidates(rpId, allow)).length === 0) {
        return { outcome: "fallback" };
      }
    }

    const unlocksAtStart = (await this.#vault.unlockCount()) ?? 0;
    const decision = await this.#windows.ask({
      request,
      origin: url.origin,
      rpId,
      tabId,
      unlocksAtStart,
    });

    return this.#ceremony.complete(
      request,
      url.origin,
      rpId,
      decision,
      unlocksAtStart,
    );
  }

  /**
   * ### registerConditional
   *
   * Takes over a page's autofill (conditional mediation) sign-in when keymember holds a passkey
   * that can answer it, so the passkey shows up in the inline menu; otherwise the browser keeps
   * the request. Requests that require user verification stay with the browser, since picking
   * from an autofill list proves presence, not identity.
   *
   * @param request Validated request
   * @param pageUrl URL of the requesting (top-level) frame, from the browser
   * @param tabId Requesting tab
   * @returns `registered`, or a reply for the page (fallback or error)
   */
  async registerConditional(
    request: PasskeyConditionalRequest,
    pageUrl: string,
    tabId: number,
  ): Promise<PasskeyReply | { outcome: "registered" }> {
    if (request.type === "passkey-conditional-cancel") {
      const stored = await this.#conditional.get(tabId);

      if (stored?.requestId === request.requestId) {
        await this.#conditional.forget(tabId);
      }

      return { outcome: "fallback" };
    }

    const url = new URL(pageUrl);
    const rpId = request.options.rpId ?? url.hostname;

    if (!rpIdAllowed(rpId, url.origin)) {
      return errorReply(
        "SecurityError",
        "The relying party id is not valid for this origin.",
      );
    }

    const allow = request.options.allowCredentials.map((entry) => entry.id);

    if (
      request.options.userVerification === "required" ||
      (await this.#vault.state()).user === undefined ||
      (await this.#passkeys.passkeyCandidates(rpId, allow)).length === 0
    ) {
      return { outcome: "fallback" };
    }

    await this.#conditional.set(tabId, {
      requestId: request.requestId,
      origin: url.origin,
      rpId,
      challenge: request.options.challenge,
      allowCredentials: allow,
    });

    return { outcome: "registered" };
  }

  /**
   * ### conditionalPasskeys
   *
   * Passkeys the inline menu may offer in a tab's top frame for its waiting autofill sign-in.
   *
   * @param tabId Tab the menu is in
   * @param frameId Frame the menu is in; only the top frame
   * @param frameUrl URL of that frame, from the browser
   * @returns The passkeys, empty when nothing is waiting
   */
  async conditionalPasskeys(
    tabId: number,
    frameId: number,
    frameUrl: string,
  ): Promise<Array<MenuPasskey>> {
    const stored = await this.#conditional.get(tabId);

    if (
      stored === undefined ||
      frameId !== 0 ||
      new URL(frameUrl).origin !== stored.origin
    ) {
      return [];
    }

    return (
      await this.#passkeys.passkeyCandidates(stored.rpId, [
        ...stored.allowCredentials,
      ])
    ).map((candidate) => ({
      itemId: candidate.itemId,
      credentialId: candidate.credentialId,
      userName: candidate.userName,
      title: candidate.title,
    }));
  }

  /**
   * ### completeConditional
   *
   * Signs the waiting autofill sign-in with the passkey the user picked in the inline menu and
   * delivers the credential to the page. The flag for user verification is not set: picking from
   * the menu shows the user is present, not who they are.
   *
   * @param tabId Tab the menu is in
   * @param frameUrl URL of the top frame, from the browser
   * @param itemId Item holding the passkey
   * @param credentialId Chosen passkey
   * @returns Whether a credential was delivered
   */
  async completeConditional(
    tabId: number,
    frameUrl: string,
    itemId: string,
    credentialId: string,
  ): Promise<boolean> {
    const stored = await this.#conditional.get(tabId);
    const challenge =
      stored === undefined ? undefined : fromBase64Url(stored.challenge);

    if (
      stored === undefined ||
      challenge === undefined ||
      new URL(frameUrl).origin !== stored.origin
    ) {
      return false;
    }

    const passkey = await this.#passkeys.findPasskey(itemId, credentialId);

    // Only a passkey for this relying party that the request allows can answer it
    if (
      passkey?.rpId !== stored.rpId ||
      (stored.allowCredentials.length > 0 &&
        !stored.allowCredentials.includes(passkey.credentialId))
    ) {
      return false;
    }

    const reply = assertionReply(passkey, {
      origin: stored.origin,
      rpId: stored.rpId,
      challenge,
      userVerified: false,
    });

    await this.#conditional.forget(tabId);
    await chrome.tabs.sendMessage(
      tabId,
      {
        type: "passkey-conditional-result",
        requestId: stored.requestId,
        reply,
      },
      { frameId: 0 },
    );

    return true;
  }
  /**
   * ### forgetConditional
   *
   * Drops a tab's waiting autofill sign-in, e.g. when the tab navigates away.
   *
   * @param tabId Tab
   */
  async forgetConditional(tabId: number): Promise<void> {
    await this.#conditional.forget(tabId);
  }

  /**
   * ### view
   *
   * What the consent window shows for a pending request.
   *
   * @param id Request id from the window URL
   * @returns The view, or `undefined` when the request is gone
   */
  async view(id: string): Promise<PasskeyRequestView | undefined> {
    const pending = this.#windows.waiting(id);

    if (pending === undefined) {
      return undefined;
    }

    const unlocked = (await this.#vault.state()).user !== undefined;
    const { request } = pending;
    const allow =
      request.type === "passkey-get"
        ? request.options.allowCredentials.map((entry) => entry.id)
        : [];

    return {
      kind: request.type === "passkey-create" ? "create" : "get",
      rpId: pending.rpId,
      origin: pending.origin,
      unlocked,
      // User verification means the password was entered for this very request
      needsReverify:
        request.options.userVerification === "required" &&
        ((await this.#vault.unlockCount()) ?? 0) <= pending.unlocksAtStart,
      candidates:
        unlocked && request.type === "passkey-get"
          ? await this.#passkeys.passkeyCandidates(pending.rpId, allow)
          : [],
      targets:
        unlocked && request.type === "passkey-create"
          ? await this.#passkeys.passkeyTargets(pending.origin)
          : [],
      vaults: unlocked ? await this.#passkeys.writableVaults() : [],
      ...(request.type === "passkey-create"
        ? { userName: request.options.user.name }
        : {}),
    };
  }

  /**
   * ### decide
   *
   * Records the user's choice from the consent window.
   *
   * @param id Request id
   * @param decision The choice
   */
  decide(id: string, decision: PasskeyDecision): void {
    this.#windows.decide(id, decision);
  }

  /**
   * ### windowClosed
   *
   * Treats closing a consent window as cancelling its request.
   *
   * @param windowId Closed window
   */
  windowClosed(windowId: number): void {
    this.#windows.windowClosed(windowId);
  }
}
