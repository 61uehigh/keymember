/**
 * ### KeymemberCryptoError
 *
 * Base class for every failure raised by the cryptographic core.
 * Catch this type to handle any core failure without depending on the concrete subclass.
 */
export class KeymemberCryptoError extends Error {
  /**
   * ### constructor
   *
   * Creates the error with a message and an optional underlying cause.
   *
   * @param message Human-readable description of the failure
   * @param options Standard error options carrying the underlying `cause`
   */
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

/**
 * ### DecryptionError
 *
 * Raised when a ciphertext fails authentication: wrong key, tampered bytes,
 * or a ciphertext moved into a context (AAD) it was not sealed for.
 * The core never distinguishes these cases, so callers cannot become a decryption oracle.
 */
export class DecryptionError extends KeymemberCryptoError {}

/**
 * ### KdfParametersRejectedError
 *
 * Raised when KDF parameters fall outside the hard-coded bounds.
 * Parameters below the floor indicate a downgrade attempt by the server and must abort login.
 */
export class KdfParametersRejectedError extends KeymemberCryptoError {}

/**
 * ### MalformedDataError
 *
 * Raised when stored or received data does not have the expected structure,
 * such as an envelope with an unknown version or a truncated wrapped key.
 */
export class MalformedDataError extends KeymemberCryptoError {}
