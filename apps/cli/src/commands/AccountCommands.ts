import { writeFile } from "node:fs/promises";

import {
  bootstrapOrganization,
  parseInviteLink,
  recoverAccount,
  renderEmergencyKit,
  signUp,
} from "@keymember/client";
import type { DeviceTrust, Session } from "@keymember/client";
import { formatSecretKey, parseSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";

import { loadConfig, saveConfig } from "../CliConfig.js";
import type { CliConfig } from "../CliConfig.js";
import type { CliDependencies } from "../CliDependencies.js";
import type { SessionRunner } from "../SessionRunner.js";

/**
 * ### AccountCommands
 *
 * Commands that set up this device and its account: pointing it at a server, creating or
 * joining the organisation, adding the account to a new device, re-enrolling after a recovery,
 * pinning the owner's key and two-factor login.
 */
export class AccountCommands {
  readonly #deps: Pick<CliDependencies, "io" | "configPath" | "kitDirectory">;
  readonly #sessions: Pick<
    SessionRunner,
    "requireConfig" | "transport" | "logIn" | "withSession"
  >;
  readonly #trust: Pick<DeviceTrust, "adoptRoots" | "afterUnlock" | "pinOwner">;

  /**
   * ### constructor
   *
   * @param deps Terminal, config location and Emergency Kit directory
   * @param sessions Config loading and login
   * @param trust How this device comes to trust the organisation's keys
   */
  constructor(
    deps: Pick<CliDependencies, "io" | "configPath" | "kitDirectory">,
    sessions: Pick<
      SessionRunner,
      "requireConfig" | "transport" | "logIn" | "withSession"
    >,
    trust: Pick<DeviceTrust, "adoptRoots" | "afterUnlock" | "pinOwner">,
  ) {
    this.#deps = deps;
    this.#sessions = sessions;
    this.#trust = trust;
  }

  /**
   * ### init
   *
   * Points this device at a server.
   *
   * @param serverUrl Server origin
   */
  async init(serverUrl: string): Promise<void> {
    const existing = await loadConfig(this.#deps.configPath);

    await saveConfig(this.#deps.configPath, {
      serverUrl,
      deviceId: existing?.deviceId ?? crypto.randomUUID(),
      roots: existing?.roots ?? {},
      ...(existing?.email === undefined ? {} : { email: existing.email }),
      ...(existing?.secretKey === undefined
        ? {}
        : { secretKey: existing.secretKey }),
    });
    this.#deps.io.print(`Server set to ${serverUrl}`);
  }

  /**
   * ### bootstrap
   *
   * Creates the organisation with this user as owner, certifies the owner's keys and pins
   * them as this device's trust root. The server's bootstrap token comes from
   * `KEYMEMBER_BOOTSTRAP_TOKEN`.
   *
   * @param orgName Organisation name
   * @param email Owner's email
   * @param name Owner's display name
   */
  async bootstrap(orgName: string, email: string, name: string): Promise<void> {
    const config = await this.#sessions.requireConfig();
    const password = await this.#askNewPassword();
    const account = await bootstrapOrganization(
      this.#sessions.transport(config),
      orgName,
      { email, name, password },
      // The token the server printed when it started, or the one its operator configured
      process.env.KEYMEMBER_BOOTSTRAP_TOKEN,
    );
    const saved = await this.#storeAccount(config, email, account.secretKey);
    const session = await this.#sessions.logIn(saved, password);

    try {
      await session.orgAdmin().initializeOrganization();
      // The owner is the organisation's root; saving it spares the owner's other devices a check
      await this.#trust.adoptRoots(
        session,
        new Map([[session.user.id, session.signingPublicKey]]),
      );
      this.#deps.io.print(
        `Organisation "${orgName}" created. Your fingerprint: ${session.fingerprint}`,
      );
      this.#deps.io.print(
        "Share this fingerprint with members so they can verify your key when they join.",
      );
    } finally {
      await session.logOut();
    }
  }

  /**
   * ### signup
   *
   * Accepts an invite on this device, then pins the owner's key after the user confirms its fingerprint.
   *
   * @param inviteToken Token from the invite
   * @param email Email the invite was sent to
   * @param name Display name
   */
  async signup(
    inviteToken: string,
    email: string,
    name: string,
  ): Promise<void> {
    const config = await this.#sessions.requireConfig();
    const password = await this.#askNewPassword();
    const account = await signUp(
      this.#sessions.transport(config),
      inviteToken,
      { email, name, password },
    );
    const saved = await this.#storeAccount(config, email, account.secretKey);
    const session = await this.#sessions.logIn(saved, password);

    try {
      this.#deps.io.print(`Your fingerprint: ${session.fingerprint}`);
      this.#deps.io.print(
        "Read it to an admin; they confirm it when certifying you.",
      );
      await this.#confirmOwner(session);
    } finally {
      await session.logOut();
    }
  }

  /**
   * ### signupWithLink
   *
   * Accepts an invite from the link an admin sent. The link proves the new keys to that admin's
   * app and carries the organisation keys to trust, so nobody compares a fingerprint. Points
   * this device at the link's server when it has none yet.
   *
   * @param url Invite link
   * @param name Display name
   */
  async signupWithLink(url: string, name: string): Promise<void> {
    const link = parseInviteLink(url);

    if (link === undefined) {
      throw new Error("That is not a keymember invite link");
    }

    const existing = await loadConfig(this.#deps.configPath);

    if (
      existing !== undefined &&
      new URL(existing.serverUrl).origin !== link.serverUrl
    ) {
      throw new Error(
        `This device uses ${existing.serverUrl} but the invite is for ${link.serverUrl}; run \`keymember init ${link.serverUrl}\` first`,
      );
    }

    if (existing === undefined) {
      await this.init(link.serverUrl);
    }

    const config = await this.#sessions.requireConfig();
    const password = await this.#askNewPassword();
    const account = await signUp(
      this.#sessions.transport(config),
      link.token,
      { email: link.email, name, password },
      link.secret,
    );
    const saved = await this.#storeAccount(
      config,
      link.email,
      account.secretKey,
    );
    const session = await this.#sessions.logIn(saved, password);

    try {
      await this.#trust.adoptRoots(session, link.roots);
      this.#deps.io.print(
        "Joined. The admin who invited you certifies you automatically the next time they open keymember.",
      );
    } finally {
      await session.logOut();
    }
  }

  /**
   * ### addDevice
   *
   * Sets up an existing account on a new device from its Emergency Kit.
   *
   * @param email Account email
   * @param secretKeyText Secret Key as printed on the kit
   */
  async addDevice(email: string, secretKeyText: string): Promise<void> {
    const config = await this.#sessions.requireConfig();
    const secretKey = parseSecretKey(secretKeyText);

    if (secretKey === undefined) {
      throw new Error("That is not a valid Secret Key");
    }

    const saved: CliConfig = {
      ...config,
      email,
      secretKey: formatSecretKey(secretKey),
    };

    await saveConfig(this.#deps.configPath, saved);

    await this.#sessions.withSession(async (session) => {
      // Roots this account saved on another device need no fingerprint comparison
      if (await this.#trust.afterUnlock(session)) {
        this.#deps.io.print("This device trusts your organisation's keys");

        return;
      }

      await this.#confirmOwner(session);
    });
  }

  /**
   * ### recover
   *
   * Member side of a recovery: re-enrols this device's account with new credentials.
   *
   * @param recoveryToken Token an admin handed over
   */
  async recover(recoveryToken: string): Promise<void> {
    const config = await this.#sessions.requireConfig();
    const password = await this.#askNewPassword();
    const account = await recoverAccount(
      this.#sessions.transport(config),
      recoveryToken,
      password,
    );
    const saved = await this.#storeAccount(
      config,
      account.email,
      account.secretKey,
    );
    const session = await this.#sessions.logIn(saved, password);

    try {
      this.#deps.io.print(`Your new fingerprint: ${session.fingerprint}`);
      this.#deps.io.print(
        "Read it to an admin so they can certify you and finish the recovery.",
      );
    } finally {
      await session.logOut();
    }
  }

  /**
   * ### pinOwner
   *
   * Pins the owner's key on a device that skipped it during sign-up.
   */
  async pinOwner(): Promise<void> {
    await this.#sessions.withSession(async (session) => {
      await this.#confirmOwner(session);
    });
  }

  /**
   * ### fingerprint
   *
   * Prints the fingerprint of this account's keys.
   */
  async fingerprint(): Promise<void> {
    await this.#sessions.withSession((session) => {
      this.#deps.io.print(session.fingerprint);

      return Promise.resolve();
    });
  }

  /**
   * ### setupTotp
   *
   * Enables two-factor login with an authenticator app.
   */
  async setupTotp(): Promise<void> {
    await this.#sessions.withSession(async (session) => {
      const { secret, uri } = await session.setupTotp();

      this.#deps.io.print(
        `Add this to your authenticator app:\n${uri}\n(secret: ${secret})`,
      );
      await session.confirmTotp(await this.#deps.io.ask("Code from the app: "));
      this.#deps.io.print("Two-factor login enabled");
    });
  }

  /**
   * ### #askNewPassword
   *
   * Asks for a new password twice and checks a minimum length.
   *
   * @returns The confirmed password
   */
  async #askNewPassword(): Promise<string> {
    const password = await this.#deps.io.askSecret("New account password: ");

    if (password.length < 12) {
      throw new Error("Use at least 12 characters");
    }

    if ((await this.#deps.io.askSecret("Repeat password: ")) !== password) {
      throw new Error("Passwords do not match");
    }

    return password;
  }

  /**
   * ### #storeAccount
   *
   * Saves the new account to the config and writes its Emergency Kit.
   *
   * @param config Current config
   * @param email Account email
   * @param secretKey New Secret Key
   * @returns The updated config
   */
  async #storeAccount(
    config: CliConfig,
    email: string,
    secretKey: SecretKey,
  ): Promise<CliConfig> {
    const saved: CliConfig = {
      ...config,
      email,
      secretKey: formatSecretKey(secretKey),
    };
    const kitPath = `${this.#deps.kitDirectory}/keymember-emergency-kit-${email}.pdf`;

    await saveConfig(this.#deps.configPath, saved);
    await writeFile(
      kitPath,
      await renderEmergencyKit({
        serverUrl: config.serverUrl,
        email,
        secretKey,
        createdAt: new Date(),
      }),
      { mode: 0o600 },
    );
    this.#deps.io.print(`Secret Key: ${formatSecretKey(secretKey)}`);
    this.#deps.io.print(
      `Emergency Kit written to ${kitPath} — print it, store it offline, then delete the file.`,
    );

    return saved;
  }

  /**
   * ### #confirmOwner
   *
   * Pins the owner's signing key after the user confirms its fingerprint out of band.
   * Without a pinned root, the device verifies nobody and refuses to share keys.
   *
   * @param session Logged-in session
   */
  async #confirmOwner(session: Session): Promise<void> {
    const [owner] = await session.ownerCandidates();

    if (owner === undefined) {
      throw new Error("The server reports no owner");
    }

    this.#deps.io.print(
      `Owner ${owner.email} fingerprint: ${owner.fingerprint}`,
    );

    const answer = await this.#deps.io.ask(
      "Does this match the fingerprint the owner gave you? (yes/no) ",
    );

    if (answer.trim().toLowerCase() !== "yes") {
      this.#deps.io.print(
        "Not pinned. Run `keymember pin-owner` once you have verified it.",
      );

      return;
    }

    await this.#trust.pinOwner(session, owner.userId, owner.fingerprint);
    this.#deps.io.print("Owner key pinned");
  }
}
