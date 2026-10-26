import { z } from "zod";

export type { UnlockResult } from "@keymember/client";

export {
  IPC_CHANNEL,
  SIGN_ANSWER_CHANNEL,
  SIGN_REQUEST_CHANNEL,
  STATE_CHANGED_CHANNEL,
} from "./channels.js";

/**
 * ### desktopRequestSchema
 *
 * Every request the window may make. The main process validates each one; the window gets
 * listings and metadata back, never a password or private key.
 */
export const desktopRequestSchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("state") }),
  z.object({ type: z.literal("configure"), serverUrl: z.string().max(500) }),
  z.object({
    type: z.literal("unlock"),
    email: z.string().max(320),
    password: z.string().max(1024),
    secretKey: z.string().max(100).optional(),
    totp: z.string().max(10).optional(),
  }),
  z.object({ type: z.literal("unlock-biometric") }),
  z.object({ type: z.literal("set-biometric"), enabled: z.boolean() }),
  z.object({ type: z.literal("lock") }),
  z.object({ type: z.literal("owner-candidates") }),
  z.object({
    type: z.literal("pin-owner"),
    userId: z.string(),
    fingerprint: z.string().max(100),
  }),
  z.object({ type: z.literal("search"), query: z.string().max(200) }),
  z.object({
    type: z.literal("copy"),
    itemId: z.string(),
    field: z.enum(["username", "password", "totp", "publicKey"]),
  }),
  z.object({ type: z.literal("ssh-keys") }),
  z.object({ type: z.literal("writable-vaults") }),
  z.object({
    type: z.literal("add-ssh-key"),
    vaultId: z.string(),
    title: z.string().min(1).max(200),
    privateKey: z.string().max(20_000).optional(),
  }),
  z.object({ type: z.literal("agent-info") }),
]);

/**
 * ### DesktopRequest
 *
 * A request from the window.
 */
export type DesktopRequest = z.infer<typeof desktopRequestSchema>;

/**
 * ### signAnswerSchema
 *
 * The user's answer to an SSH signature request.
 */
export const signAnswerSchema = z.object({
  id: z.string(),
  answer: z.enum(["session", "once", "deny"]),
});

/**
 * ### DesktopState
 *
 * What the window shows about the app.
 */
export interface DesktopState {
  readonly serverUrl?: string;
  readonly email?: string;
  readonly knownDevice: boolean;
  readonly pinned: boolean;
  readonly biometricAvailable: boolean;
  readonly biometricEnabled: boolean;
  readonly user?: { readonly name: string; readonly email: string };
}

/**
 * ### ItemRow
 *
 * An item as listed in the window: never a secret.
 */
export interface ItemRow {
  readonly id: string;
  readonly title: string;
  readonly type: string;
  readonly vaultName: string;
  readonly username?: string;
  readonly hasPassword: boolean;
  readonly hasTotp: boolean;
}

/**
 * ### SshKeyRow
 *
 * An SSH key as listed in the window: public parts only.
 */
export interface SshKeyRow {
  readonly id: string;
  readonly title: string;
  readonly vaultName: string;
  readonly fingerprint: string;
  readonly publicKey: string;
}

/**
 * ### SignRequestView
 *
 * What the window shows when an SSH client asks for a signature.
 */
export interface SignRequestView {
  readonly id: string;
  readonly title: string;
  readonly fingerprint: string;
}

/**
 * ### AgentInfo
 *
 * How to point SSH at the agent.
 */
export interface AgentInfo {
  readonly socketPath: string;
  /** Why the agent is not running, when it could not start */
  readonly error?: string;
}

/**
 * ### KeymemberBridge
 *
 * What the preload script exposes to the window as `window.keymember`.
 */
export interface KeymemberBridge {
  request(request: DesktopRequest): Promise<unknown>;
  onSignRequest(listener: (request: SignRequestView) => void): void;
  answerSignRequest(id: string, answer: "session" | "once" | "deny"): void;

  /**
   * ### onStateChanged
   *
   * Calls `listener` when the main process changed the state on its own, such as locking.
   *
   * @param listener Called with no arguments
   */
  onStateChanged(listener: () => void): void;
}
