import { z } from "zod";

/**
 * ### fieldKindSchema
 *
 * What a focused input is for. Decides which values a fill may write into the page.
 */
export const fieldKindSchema = z.enum(["username", "password", "otp"]);

/**
 * ### FieldKind
 *
 * Kind of a detected login field.
 */
export type FieldKind = z.infer<typeof fieldKindSchema>;

/**
 * ### popupRequestSchema
 *
 * Requests the popup sends to the background. The background accepts them only from the
 * extension's own popup page.
 */
export const popupRequestSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("state") }),
  z.object({ type: z.literal("configure"), serverUrl: z.url() }),
  z.object({
    type: z.literal("unlock"),
    email: z.string().min(1),
    password: z.string().min(1),
    secretKey: z.string().optional(),
    totp: z.string().optional(),
  }),
  z.object({ type: z.literal("owner-candidates") }),
  z.object({
    type: z.literal("pin-owner"),
    userId: z.string(),
    fingerprint: z.string().max(100),
  }),
  z.object({ type: z.literal("lock") }),
  // The popup copied a secret; the background clears it from the clipboard later
  z.object({ type: z.literal("copied"), value: z.string().max(10_000) }),
  z.object({ type: z.literal("forget-device") }),
  z.object({ type: z.literal("matches") }),
  z.object({ type: z.literal("search"), query: z.string().max(200) }),
  z.object({
    type: z.literal("reveal"),
    itemId: z.string(),
    field: z.enum(["username", "password", "totp"]),
  }),
  z.object({ type: z.literal("fill"), itemId: z.string() }),
  z.object({ type: z.literal("pending") }),
  z.object({
    type: z.literal("save-pending"),
    id: z.string(),
    vaultId: z.string().optional(),
  }),
  z.object({ type: z.literal("dismiss-pending"), id: z.string() }),
  z.object({
    type: z.literal("generate"),
    length: z.number().int().min(8).max(128),
    symbols: z.boolean(),
  }),
]);

/**
 * ### PopupRequest
 *
 * A request from the popup.
 */
export type PopupRequest = z.infer<typeof popupRequestSchema>;

/**
 * ### contentRequestSchema
 *
 * Requests content scripts send to the background. The page URL is never taken from these;
 * the background reads it from the browser-supplied sender.
 */
export const contentRequestSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("menu-open"), kind: fieldKindSchema }),
  z.object({
    type: z.literal("save-candidate"),
    username: z.string().max(500).optional(),
    password: z.string().min(1).max(500),
  }),
]);

/**
 * ### ContentRequest
 *
 * A request from a content script.
 */
export type ContentRequest = z.infer<typeof contentRequestSchema>;

const b64Text = z
  .string()
  .regex(/^[A-Za-z0-9_-]*$/)
  .max(4096);

/**
 * ### menuRequestSchema
 *
 * Requests the inline menu iframe sends to the background, authorised by the one-time
 * token the background issued to the content script that opened the menu.
 */
export const menuRequestSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("menu-items"), token: z.string().min(16) }),
  z.object({
    type: z.literal("menu-fill"),
    token: z.string().min(16),
    itemId: z.string(),
  }),
  z.object({ type: z.literal("menu-close"), token: z.string().min(16) }),
  z.object({
    type: z.literal("menu-passkey"),
    token: z.string().min(16),
    itemId: z.string(),
    credentialId: b64Text,
  }),
]);

/**
 * ### MenuRequest
 *
 * A request from the inline menu.
 */
export type MenuRequest = z.infer<typeof menuRequestSchema>;

/**
 * ### contentCommandSchema
 *
 * Commands the background sends to a content script. `expectedUrl` is the frame URL the
 * background matched against; the content script refuses to fill if the frame navigated since.
 */
export const contentCommandSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("fill"),
    expectedUrl: z.string(),
    kind: fieldKindSchema.optional(),
    username: z.string().optional(),
    password: z.string().optional(),
    totp: z.string().optional(),
  }),
  z.object({ type: z.literal("close-menu") }),
]);

/**
 * ### ContentCommand
 *
 * A command to a content script.
 */
export type ContentCommand = z.infer<typeof contentCommandSchema>;

/**
 * ### ItemRow
 *
 * What the popup and the menu may show about an item: never a password.
 */
export interface ItemRow {
  /**
   * ### id
   *
   * Item id.
   */
  readonly id: string;

  /**
   * ### title
   *
   * Item title.
   */
  readonly title: string;

  /**
   * ### username
   *
   * User name, if the item has one.
   */
  readonly username?: string;

  /**
   * ### vaultName
   *
   * Name of the vault holding the item.
   */
  readonly vaultName: string;

  /**
   * ### hasTotp
   *
   * Whether the item can produce a two-factor code.
   */
  readonly hasTotp: boolean;

  /**
   * ### insecure
   *
   * Whether the item was saved for https but the page is http; such items are listed but never filled.
   */
  readonly insecure: boolean;
}

/**
 * ### ExtensionState
 *
 * Lock state reported to the popup.
 */
export interface ExtensionState {
  /**
   * ### serverUrl
   *
   * Configured server, if any.
   */
  readonly serverUrl?: string;

  /**
   * ### email
   *
   * Remembered account email.
   */
  readonly email?: string;

  /**
   * ### knownDevice
   *
   * Whether the Secret Key is stored, so the popup does not ask for it.
   */
  readonly knownDevice: boolean;

  /**
   * ### pinned
   *
   * Whether an owner key is pinned. Without it nothing is verified and sharing is refused.
   */
  readonly pinned: boolean;

  /**
   * ### user
   *
   * The unlocked user, or `undefined` while locked.
   */
  readonly user?: { readonly name: string; readonly email: string };
}

/**
 * ### passkeyCreateOptionsSchema
 *
 * `PublicKeyCredentialCreationOptions` as serialised by the page script, binary values in base64url.
 */
export const passkeyCreateOptionsSchema = z.object({
  rp: z.object({
    id: z.string().max(253).optional(),
    name: z.string().max(200),
  }),
  user: z.object({
    id: b64Text,
    name: z.string().max(200),
    displayName: z.string().max(200),
  }),
  challenge: b64Text,
  pubKeyCredParams: z
    .array(z.object({ type: z.string(), alg: z.number() }))
    .max(20),
  excludeCredentials: z.array(z.object({ id: b64Text })).max(100),
  userVerification: z.enum(["required", "preferred", "discouraged"]).optional(),
  timeout: z.number().int().positive().max(600_000).optional(),
});

/**
 * ### passkeyGetOptionsSchema
 *
 * `PublicKeyCredentialRequestOptions` as serialised by the page script.
 */
export const passkeyGetOptionsSchema = z.object({
  rpId: z.string().max(253).optional(),
  challenge: b64Text,
  allowCredentials: z.array(z.object({ id: b64Text })).max(100),
  userVerification: z.enum(["required", "preferred", "discouraged"]).optional(),
  timeout: z.number().int().positive().max(600_000).optional(),
});

/**
 * ### passkeyContentRequestSchema
 *
 * Passkey requests forwarded by the content script from the page's `navigator.credentials` call.
 */
export const passkeyContentRequestSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("passkey-create"),
    options: passkeyCreateOptionsSchema,
  }),
  z.object({
    type: z.literal("passkey-get"),
    options: passkeyGetOptionsSchema,
  }),
]);

/**
 * ### passkeyConditionalRequestSchema
 *
 * Conditional-mediation (autofill) sign-in requests from the content script: register one that
 * stays open until the user picks a passkey in the inline menu, or cancel it when the page aborts.
 */
export const passkeyConditionalRequestSchema = z.discriminatedUnion("type", [
  z.object({
    type: z.literal("passkey-conditional"),
    requestId: z.string().min(16).max(64),
    options: passkeyGetOptionsSchema,
  }),
  z.object({
    type: z.literal("passkey-conditional-cancel"),
    requestId: z.string().min(16).max(64),
  }),
]);

/**
 * ### PasskeyConditionalRequest
 *
 * A conditional-mediation request from a content script.
 */
export type PasskeyConditionalRequest = z.infer<
  typeof passkeyConditionalRequestSchema
>;

/**
 * ### MenuPasskey
 *
 * A passkey the inline menu offers for a waiting autofill sign-in.
 */
export interface MenuPasskey {
  readonly itemId: string;
  readonly credentialId: string;
  readonly userName: string;
  readonly title: string;
}

/**
 * ### PasskeyContentRequest
 *
 * A passkey request from a content script.
 */
export type PasskeyContentRequest = z.infer<typeof passkeyContentRequestSchema>;

/**
 * ### passkeyDecisionSchema
 *
 * What the user chose in the consent window.
 */
export const passkeyDecisionSchema = z.discriminatedUnion("action", [
  z.object({
    action: z.literal("create"),
    itemId: z.string().optional(),
    vaultId: z.string().optional(),
  }),
  z.object({
    action: z.literal("use"),
    itemId: z.string(),
    credentialId: z.string(),
  }),
  z.object({ action: z.literal("fallback") }),
  z.object({ action: z.literal("cancel") }),
]);

/**
 * ### PasskeyDecision
 *
 * The user's choice for a passkey request.
 */
export type PasskeyDecision = z.infer<typeof passkeyDecisionSchema>;

/**
 * ### passkeyWindowRequestSchema
 *
 * Requests from the passkey consent window, which may also send any popup request (to unlock).
 */
export const passkeyWindowRequestSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("passkey-request"), id: z.string() }),
  z.object({
    type: z.literal("passkey-decide"),
    id: z.string(),
    decision: passkeyDecisionSchema,
  }),
]);

/**
 * ### PasskeyWindowRequest
 *
 * A request from the consent window.
 */
export type PasskeyWindowRequest = z.infer<typeof passkeyWindowRequestSchema>;

/**
 * ### PasskeyReply
 *
 * The background's answer to a page's passkey call: a credential (binary values in base64url),
 * an instruction to let the browser's own passkey UI handle it, or a DOMException to throw.
 */
export type PasskeyReply =
  | {
      readonly outcome: "credential";
      readonly credential: Readonly<
        Record<string, string | number | Array<string>>
      >;
    }
  | { readonly outcome: "fallback" }
  | {
      readonly outcome: "error";
      readonly name: string;
      readonly message: string;
    };

/**
 * ### PasskeyRequestView
 *
 * What the consent window shows about a pending request.
 */
export interface PasskeyRequestView {
  readonly kind: "create" | "get";
  readonly rpId: string;
  readonly origin: string;
  readonly userName?: string;
  readonly unlocked: boolean;
  readonly needsReverify: boolean;
  readonly candidates: ReadonlyArray<{
    itemId: string;
    title: string;
    userName: string;
    credentialId: string;
  }>;
  readonly targets: ReadonlyArray<{
    itemId: string;
    title: string;
    username?: string;
  }>;
  readonly vaults: ReadonlyArray<{ id: string; name: string }>;
}
