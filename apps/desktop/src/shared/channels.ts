/**
 * ### IPC_CHANNEL
 *
 * The one channel the window uses to ask the main process for anything.
 */
export const IPC_CHANNEL = "keymember";

/**
 * ### SIGN_REQUEST_CHANNEL
 *
 * Main-to-window channel asking the user to approve an SSH signature.
 */
export const SIGN_REQUEST_CHANNEL = "keymember-sign-request";

/**
 * ### SIGN_ANSWER_CHANNEL
 *
 * Window-to-main channel with the user's answer to an SSH signature request.
 */
export const SIGN_ANSWER_CHANNEL = "keymember-sign-answer";

/**
 * ### STATE_CHANGED_CHANNEL
 *
 * Main-to-window channel saying the vault's state changed on its own (it locked), so the window
 * reloads its state instead of showing what it no longer may.
 */
export const STATE_CHANGED_CHANNEL = "keymember-state-changed";
