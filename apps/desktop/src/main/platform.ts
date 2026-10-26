/**
 * ### SecretBox
 *
 * Encryption tied to this OS account (the macOS Keychain). Either call throws when the OS
 * refuses, for instance when the user denies a rebuilt app access to its Keychain item.
 */
export interface SecretBox {
  encrypt(plaintext: string): Uint8Array;
  decrypt(ciphertext: Uint8Array): string;
}

/**
 * ### BiometricPrompt
 *
 * Asks for Touch ID with the given reason; resolves to whether the user passed.
 */
export type BiometricPrompt = (reason: string) => Promise<boolean>;

/**
 * ### Clipboard
 *
 * The system clipboard.
 */
export interface Clipboard {
  read(): Promise<string>;
  write(text: string): void;
}

/**
 * ### SigningDecision
 *
 * The user's answer to an SSH signature request: allow until the vault locks, allow this one
 * signature, or refuse.
 */
export type SigningDecision = "session" | "once" | "deny";

/**
 * ### ConfirmSigning
 *
 * Asks the user whether a key may sign for an SSH client.
 */
export type ConfirmSigning = (request: {
  title: string;
  fingerprint: string;
}) => Promise<SigningDecision>;

/**
 * ### PlatformServices
 *
 * Everything the desktop vault needs from the operating system, passed in so the logic can be
 * tested without Electron. Each part of the vault takes only the services it uses.
 */
export interface PlatformServices {
  /**
   * ### dataDir
   *
   * Directory for this app's files (Electron's `userData`).
   */
  readonly dataDir: string;

  /**
   * ### secretBox
   *
   * The OS secret box, or `undefined` where there is none worth the name.
   */
  readonly secretBox: SecretBox | undefined;

  /**
   * ### biometric
   *
   * Touch ID, or `undefined` on a computer without it.
   */
  readonly biometric: BiometricPrompt | undefined;

  /**
   * ### clipboard
   *
   * The system clipboard.
   */
  readonly clipboard: Clipboard;

  /**
   * ### openExternal
   *
   * Opens a URL in the default browser (identity-provider sign-in).
   */
  openExternal(url: string): void;

  /**
   * ### confirmSigning
   *
   * Asks the user before an SSH key signs.
   */
  readonly confirmSigning: ConfirmSigning;
}
