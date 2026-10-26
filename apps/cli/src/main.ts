#!/usr/bin/env node
import { spawn } from "node:child_process";

import { fetchTransport } from "@keymember/client";
import type { ImportFormat, ShareField } from "@keymember/client";
import { Command, Option } from "commander";

import { Cli } from "./Cli.js";
import { defaultConfigPath } from "./CliConfig.js";
import { terminalIo } from "./Io.js";

const cli = new Cli({
  io: terminalIo(),
  configPath: defaultConfigPath(),
  transportFor: fetchTransport,
  kitDirectory: process.cwd(),
  openUrl: (url) => {
    const [command, args]: [string, Array<string>] =
      process.platform === "darwin"
        ? ["open", [url]]
        : process.platform === "win32"
          ? ["cmd", ["/c", "start", "", url]]
          : ["xdg-open", [url]];

    // Best effort: the URL is printed as well, so a missing opener is harmless
    spawn(command, args, { stdio: "ignore", detached: true })
      .on("error", () => undefined)
      .unref();
  },
});
const program = new Command("keymember").description(
  "Team password manager with end-to-end encryption",
);
const collect = (value: string, previous: Array<string>): Array<string> => [
  ...previous,
  value,
];

program
  .command("init <server-url>")
  .description("Point this device at a keymember server")
  .action((url: string) => cli.account.init(url));

program
  .command("bootstrap")
  .description("Create the organisation on an empty server, as its owner")
  .requiredOption("--org <name>", "organisation name")
  .requiredOption("--email <email>", "owner email")
  .requiredOption("--name <name>", "owner display name")
  .action((options: { org: string; email: string; name: string }) =>
    cli.account.bootstrap(options.org, options.email, options.name),
  );

program
  .command("signup")
  .description("Accept an invite on this device")
  .option("--link <url>", "invite link the admin sent")
  .option(
    "--invite <token>",
    "invite token, when typing it in instead of a link",
  )
  .option("--email <email>", "email the invite was sent to, with --invite")
  .requiredOption("--name <name>", "display name")
  .action(
    (options: {
      link?: string;
      invite?: string;
      email?: string;
      name: string;
    }) => {
      if (options.link !== undefined) {
        return cli.account.signupWithLink(options.link, options.name);
      }

      if (options.invite === undefined || options.email === undefined) {
        throw new Error("Pass --link, or --invite with --email");
      }

      return cli.account.signup(options.invite, options.email, options.name);
    },
  );

program
  .command("add-device")
  .description(
    "Set up an existing account on this device from its Emergency Kit",
  )
  .requiredOption("--email <email>", "account email")
  .requiredOption("--secret-key <key>", "Secret Key from the Emergency Kit")
  .action((options: { email: string; secretKey: string }) =>
    cli.account.addDevice(options.email, options.secretKey),
  );

program
  .command("pin-owner")
  .description("Verify and pin the owner's key")
  .action(() => cli.account.pinOwner());
program
  .command("fingerprint")
  .description("Show this account's key fingerprint")
  .action(() => cli.account.fingerprint());
program
  .command("members")
  .description("List members and whether their keys are verified")
  .action(() => cli.org.members());

program
  .command("certify <email>")
  .description("Certify a member's keys after comparing fingerprints (admins)")
  .requiredOption(
    "--fingerprint <fingerprint>",
    "fingerprint the member read out",
  )
  .action((email: string, options: { fingerprint: string }) =>
    cli.org.certify(email, options.fingerprint),
  );

program
  .command("invite <email>")
  .description("Invite a member (admins)")
  .option("--admin", "grant the admin role", false)
  .action((email: string, options: { admin: boolean }) =>
    cli.org.invite(email, options.admin ? "admin" : "member"),
  );

const vault = program.command("vault").description("Manage vaults");

vault.command("list").action(() => cli.vaults.list());
vault
  .command("create <name>")
  .option(
    "--share <email:permission>",
    "share with a member (repeatable)",
    collect,
    [],
  )
  .option(
    "--group <group:permission>",
    "share with a group (repeatable)",
    collect,
    [],
  )
  .action(
    (name: string, options: { share: Array<string>; group: Array<string> }) =>
      cli.vaults.create(name, options.share, options.group),
  );
vault
  .command("share <vault> <target>")
  .description("Share with a member (by email) or, with --group, a group")
  .addOption(
    new Option("--permission <permission>")
      .choices(["view", "edit", "manage"])
      .default("view"),
  )
  .option("--group", "the target is a group name or id", false)
  .action(
    (
      vaultRef: string,
      target: string,
      options: { permission: "view" | "edit" | "manage"; group: boolean },
    ) => cli.vaults.share(vaultRef, target, options.permission, options.group),
  );

vault
  .command("rotate <vault>")
  .description("Replace the vault key, optionally removing members or groups")
  .option(
    "--remove <email|group>",
    "member or group to remove (repeatable)",
    collect,
    [],
  )
  .action((vaultRef: string, options: { remove: Array<string> }) =>
    cli.vaults.rotate(vaultRef, options.remove),
  );

const group = program.command("group").description("Manage groups");

group.command("list").action(() => cli.groups.list());
group
  .command("create <name>")
  .description("Create a group (admins)")
  .option("--member <email>", "initial member (repeatable)", collect, [])
  .action((name: string, options: { member: Array<string> }) =>
    cli.groups.create(name, options.member),
  );
group
  .command("add <group> <email>")
  .description("Add a member to a group (admins)")
  .action((groupRef: string, email: string) => cli.groups.add(groupRef, email));
group
  .command("remove <group> <email>")
  .description("Remove a member by rotating the group key (admins)")
  .action((groupRef: string, email: string) =>
    cli.groups.remove(groupRef, email),
  );
group
  .command("delete <group>")
  .description("Delete a group and the vault access it carried (admins)")
  .action((groupRef: string) => cli.groups.delete(groupRef));

const item = program.command("item").description("Manage items");

item
  .command("list")
  .option("--vault <vault>", "limit to one vault")
  .action((options: { vault?: string }) => cli.items.list(options.vault));
item
  .command("add <vault>")
  .requiredOption("--title <title>", "item title")
  .option("--url <url>", "site URL (repeatable)", collect, [])
  .option("--username <username>", "user name")
  .option("--notes <notes>", "notes")
  .option("--generate", "generate the password instead of asking", false)
  .action(
    (
      vaultRef: string,
      options: {
        title: string;
        url: Array<string>;
        username?: string;
        notes?: string;
        generate: boolean;
      },
    ) =>
      cli.items.add(vaultRef, {
        title: options.title,
        urls: options.url,
        generate: options.generate,
        ...(options.username === undefined
          ? {}
          : { username: options.username }),
        ...(options.notes === undefined ? {} : { notes: options.notes }),
      }),
  );
item
  .command("get <item>")
  .option(
    "--field <field>",
    "print only this field (username, password, totp, notes, url or a custom label)",
  )
  .action((itemRef: string, options: { field?: string }) =>
    cli.items.get(itemRef, options.field),
  );
item
  .command("delete <item>")
  .action((itemRef: string) => cli.items.delete(itemRef));
item
  .command("share <item>")
  .description("Make a link that opens the item without an account")
  .option(
    "--fields <list>",
    "comma-separated: username,password,totp,notes",
    "username,password",
  )
  .option("--hours <n>", "hours the link stays open (max 720)", "24")
  .option("--views <n>", "times the link can be opened (1-100)", "1")
  .option(
    "--passphrase",
    "also require a passphrase you send separately",
    false,
  )
  .action(
    (
      itemRef: string,
      options: {
        fields: string;
        hours: string;
        views: string;
        passphrase: boolean;
      },
    ) => {
      const allowed = new Set<string>([
        "username",
        "password",
        "totp",
        "notes",
      ]);
      const fields = options.fields.split(",").map((field) => field.trim());
      const unknown = fields.filter((field) => !allowed.has(field));

      if (unknown.length > 0) {
        throw new Error(`Unknown field(s): ${unknown.join(", ")}`);
      }

      return cli.items.share(itemRef, {
        // Checked against the allowed names just above
        fields: fields as Array<ShareField>,
        hours: Number(options.hours),
        views: Number(options.views),
        withPassphrase: options.passphrase,
      });
    },
  );

program
  .command("run")
  .description("Run a command with secrets as environment variables")
  .option(
    "--env <NAME=item.field>",
    "inject a secret (repeatable)",
    collect,
    [],
  )
  .argument("<command...>", "command to run, after --")
  .action(async (command: Array<string>, options: { env: Array<string> }) => {
    process.exitCode = await cli.items.run(options.env, command);
  });

program
  .command("totp-setup")
  .description("Enable two-factor login")
  .action(() => cli.account.setupTotp());

program
  .command("audit")
  .description("Show recent audit events (admins)")
  .option("--limit <n>", "number of events", "50")
  .action((options: { limit: string }) => cli.org.audit(Number(options.limit)));

program
  .command("policy")
  .description("Change organisation login policies (admins)")
  .addOption(
    new Option("--require-totp <on|off>", "require two-factor login").choices([
      "on",
      "off",
    ]),
  )
  .addOption(
    new Option(
      "--require-sso <on|off>",
      "require signing in with the company account",
    ).choices(["on", "off"]),
  )
  .action((options: { requireTotp?: string; requireSso?: string }) =>
    cli.org.setPolicy({
      requireTotp:
        options.requireTotp === undefined
          ? undefined
          : options.requireTotp === "on",
      requireSso:
        options.requireSso === undefined
          ? undefined
          : options.requireSso === "on",
    }),
  );

const member = program.command("member").description("Manage members");

member
  .command("offboard <email>")
  .description(
    "Suspend a member who left and rotate the keys they could use (admins)",
  )
  .action((email: string) => cli.org.offboard(email));

program
  .command("import <file> <vault>")
  .description(
    "Import a Chrome CSV, Bitwarden JSON, 1Password 1PUX or CXF JSON export",
  )
  .addOption(
    new Option("--format <format>").choices([
      "chrome-csv",
      "bitwarden-json",
      "1password-1pux",
      "cxf-json",
    ]),
  )
  .action(
    (
      file: string,
      vaultRef: string,
      options: {
        format?: ImportFormat;
      },
    ) => cli.items.importFile(file, vaultRef, options.format),
  );

const recovery = program
  .command("recovery")
  .description("Account recovery (admins)");

recovery.command("list").action(() => cli.recovery.list());
recovery
  .command("request <email>")
  .action((email: string) => cli.recovery.request(email));
recovery
  .command("approve <id>")
  .description("Approve a recovery another admin requested")
  .action((id: string) => cli.recovery.approve(id));
recovery
  .command("complete <id>")
  .description(
    "Restore the member's vaults and groups after re-certifying them",
  )
  .action((id: string) => cli.recovery.complete(id));
recovery.command("cancel <id>").action((id: string) => cli.recovery.cancel(id));

program
  .command("recover <token>")
  .description("Re-enrol with a recovery token from an admin")
  .action((token: string) => cli.account.recover(token));

try {
  await program.parseAsync();
} catch (error) {
  process.stderr.write(
    `error: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 1;
}
