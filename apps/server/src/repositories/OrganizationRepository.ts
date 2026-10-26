/**
 * ### OrganizationProfile
 *
 * An organisation's name, policies and the recovery key it published, if any.
 */
export interface OrganizationProfile {
  readonly id: string;
  readonly name: string;
  readonly requireTotp: boolean;
  readonly requireSso: boolean;
  readonly recoveryKey:
    | { publicKey: Uint8Array; signature: Uint8Array; signerId: string }
    | undefined;
}

/**
 * ### OrganizationRepository
 *
 * Storage of organisations, their policies and their recovery key.
 */
export interface OrganizationRepository {
  /**
   * ### hasRecoveryKey
   *
   * Whether an organisation has set up its recovery key; from then on every vault key needs a
   * copy wrapped to it.
   *
   * @param orgId Organisation
   * @returns Whether it has one
   */
  hasRecoveryKey(orgId: string): Promise<boolean>;

  /**
   * ### isBootstrapped
   *
   * Whether the server has an organisation yet, so a fresh web client knows to show the
   * bootstrap screen. Takes no lock; use {@link OrganizationRepository.lockForBootstrap} to act on it.
   *
   * @returns Whether an organisation exists
   */
  isBootstrapped(): Promise<boolean>;

  /**
   * ### lockForBootstrap
   *
   * Serialises bootstrap attempts for the rest of the transaction, so only one organisation can
   * ever be created, and says whether one already exists.
   *
   * @returns Whether the server already has an organisation
   */
  lockForBootstrap(): Promise<boolean>;

  /**
   * ### insert
   *
   * Creates the organisation.
   *
   * @param orgId Id
   * @param name Display name
   */
  insert(orgId: string, name: string): Promise<void>;

  /**
   * ### profile
   *
   * An organisation's name, policies and published recovery key.
   *
   * @param orgId Organisation
   * @returns The profile, or `undefined`
   */
  profile(orgId: string): Promise<OrganizationProfile | undefined>;

  /**
   * ### lockRecoveryKey
   *
   * Locks an organisation for setting its recovery key.
   *
   * @param orgId Organisation
   * @returns Whether it already has one, or `undefined` for an unknown organisation
   */
  lockRecoveryKey(orgId: string): Promise<boolean | undefined>;

  /**
   * ### setRecoveryKey
   *
   * Publishes the recovery public key with the owner's signature.
   *
   * @param orgId Organisation
   * @param key Public key, signature and signer
   */
  setRecoveryKey(
    orgId: string,
    key: { publicKey: Uint8Array; signature: Uint8Array; signerId: string },
  ): Promise<void>;

  /**
   * ### recoveryKeyCopy
   *
   * An admin's copy of the recovery private key.
   *
   * @param orgId Organisation
   * @param adminId Admin
   * @returns The wrapped key, or `undefined` when they hold none
   */
  recoveryKeyCopy(
    orgId: string,
    adminId: string,
  ): Promise<Uint8Array | undefined>;

  /**
   * ### putRecoveryKeyCopy
   *
   * Gives an admin their copy of the recovery private key, replacing an older one.
   *
   * @param orgId Organisation
   * @param adminId Admin
   * @param wrappedPrivateKey Recovery private key wrapped to the admin
   */
  putRecoveryKeyCopy(
    orgId: string,
    adminId: string,
    wrappedPrivateKey: Uint8Array,
  ): Promise<void>;

  /**
   * ### updatePolicies
   *
   * Changes the given policies, leaving the others as they are.
   *
   * @param orgId Organisation
   * @param policies Policies to change
   */
  updatePolicies(
    orgId: string,
    policies: {
      requireTotp?: boolean | undefined;
      requireSso?: boolean | undefined;
    },
  ): Promise<void>;

  /**
   * ### removeRecoveryKeyCopies
   *
   * Drops an admin's copies of the recovery key, which were wrapped to keys they no longer have.
   *
   * @param adminId Admin
   */
  removeRecoveryKeyCopies(adminId: string): Promise<void>;
}
