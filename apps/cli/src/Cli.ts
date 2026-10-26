import { DeviceTrust } from "@keymember/client";

import { AccountCommands } from "./commands/AccountCommands.js";
import { GroupCommands } from "./commands/GroupCommands.js";
import { ItemCommands } from "./commands/ItemCommands.js";
import { OrgCommands } from "./commands/OrgCommands.js";
import { RecoveryCommands } from "./commands/RecoveryCommands.js";
import { VaultCommands } from "./commands/VaultCommands.js";
import { cliDeviceRoots } from "./CliDeviceRoots.js";
import type { CliDependencies } from "./CliDependencies.js";
import { SessionRunner } from "./SessionRunner.js";

/**
 * ### Cli
 *
 * Every `keymember` command, grouped the way the command line groups them. Each command that
 * needs the vault logs in, does its work and logs out again, so no unlocked state outlives
 * the process.
 */
export class Cli {
  /**
   * ### account
   *
   * This device and its account.
   */
  readonly account: AccountCommands;

  /**
   * ### org
   *
   * Members, invites, offboarding, audit log and policies.
   */
  readonly org: OrgCommands;

  /**
   * ### vaults
   *
   * Vaults, their sharing and key rotation.
   */
  readonly vaults: VaultCommands;

  /**
   * ### items
   *
   * Items, share links, import and `run`.
   */
  readonly items: ItemCommands;

  /**
   * ### groups
   *
   * Groups and their members.
   */
  readonly groups: GroupCommands;

  /**
   * ### recovery
   *
   * Admin side of account recovery.
   */
  readonly recovery: RecoveryCommands;

  /**
   * ### constructor
   *
   * @param deps External dependencies
   */
  constructor(deps: CliDependencies) {
    const trust = new DeviceTrust(cliDeviceRoots(deps.configPath));
    const sessions = new SessionRunner(deps, trust);
    const commandDeps = { io: deps.io, sessions };

    this.account = new AccountCommands(deps, sessions, trust);
    this.org = new OrgCommands(commandDeps);
    this.vaults = new VaultCommands(commandDeps);
    this.items = new ItemCommands(commandDeps);
    this.groups = new GroupCommands(commandDeps);
    this.recovery = new RecoveryCommands(commandDeps);
  }
}
