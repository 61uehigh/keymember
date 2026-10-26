import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  addDeviceUri,
  fetchTransport,
  openShareLink,
  parseInviteLink,
  parseShareLink,
} from "@keymember/client";
import type { Transport } from "@keymember/client";
import { generateSecretKey } from "@keymember/core";
import {
  buildApp,
  codeForStep,
  migrate,
  PgliteDatabase,
  SqlStore,
} from "@keymember/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { Cli, parseEnvMapping, readField } from "@keymember/cli";
import type { Io } from "@keymember/cli";

/**
 * ### Answer
 *
 * A queued answer to a prompt, or a function that works it out when the prompt comes, such
 * as a two-factor code from a secret printed just before.
 */
type Answer = string | (() => string);

/**
 * ### ScriptedIo
 *
 * Io that answers prompts from queues and records what was printed and warned.
 */
interface ScriptedIo {
  readonly io: Io;
  readonly answers: Array<Answer>;
  readonly secrets: Array<string>;
  readonly output: Array<string>;
  readonly warnings: Array<string>;
}

/**
 * ### scriptedIo
 *
 * Creates a {@link ScriptedIo}; a prompt with no queued answer fails the command.
 *
 * @returns The Io plus handles to feed answers and read output
 */
function scriptedIo(): ScriptedIo {
  const answers: Array<Answer> = [];
  const secrets: Array<string> = [];
  const output: Array<string> = [];
  const warnings: Array<string> = [];
  const take = (queue: Array<Answer>, question: string): Promise<string> => {
    const next = queue.shift();

    if (next === undefined) {
      return Promise.reject(new Error(`Unexpected prompt: ${question}`));
    }

    return Promise.resolve(typeof next === "function" ? next() : next);
  };

  return {
    answers,
    secrets,
    output,
    warnings,
    io: {
      print: (line) => output.push(line),
      warn: (line) => warnings.push(line),
      ask: (question) => take(answers, question),
      askSecret: (question) => take(secrets, question),
    },
  };
}

/**
 * ### base32Decode
 *
 * Decodes an RFC 4648 base32 TOTP secret, as an authenticator app would.
 *
 * @param text Base32 text
 * @returns The secret bytes
 */
function base32Decode(text: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const bytes: Array<number> = [];
  let buffer = 0;
  let bits = 0;

  for (const char of text.replace(/=+$/, "").toUpperCase()) {
    buffer = ((buffer << 5) | alphabet.indexOf(char)) & 0xffff;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }

  return Uint8Array.from(bytes);
}

/**
 * ### Member
 *
 * One person's CLI on their own device, with the scripted terminal and password it uses.
 */
interface Member extends ScriptedIo {
  readonly cli: Cli;
  readonly email: string;
  readonly password: string;
}

const DAY_MS = 24 * 60 * 60 * 1000;

// Each test sets up the members it changes, so the tests do not depend on running in order.
// The fixture all of them share is the owner, Bob (joined by link) and the vault Infra.
describe("keymember CLI against a running server", () => {
  let app: ReturnType<typeof buildApp>;
  let db: PgliteDatabase;
  let workDir: string;
  let serverUrl: string;
  // The server's clock; tests move it forward for two-factor steps and waiting periods
  let now = Date.now();
  let owner: Member;
  let bob: Member;

  /**
   * ### member
   *
   * A CLI for a person on their own device.
   *
   * @param name Short name, used for the email, password and config folder
   * @param transportFor Transport factory, to simulate network failures
   * @returns The member
   */
  const member = (
    name: string,
    transportFor: (url: string) => Transport = fetchTransport,
  ): Member => {
    const scripted = scriptedIo();

    return {
      ...scripted,
      email: `${name}@example.com`,
      password: `${name}-password-1234`,
      cli: new Cli({
        io: scripted.io,
        configPath: join(workDir, name, "config.json"),
        transportFor,
        kitDirectory: workDir,
      }),
    };
  };

  /**
   * ### as
   *
   * Runs a command that logs in, supplying the member's password.
   *
   * @param who Member running it
   * @param command Command to run
   * @returns What the command returns
   */
  const as = async <T>(
    who: Pick<Member, "password" | "secrets">,
    command: () => Promise<T>,
  ): Promise<T> => {
    who.secrets.push(who.password);

    return command();
  };

  /**
   * ### linkFor
   *
   * Has the owner invite someone and returns the printed link.
   *
   * @param email Invitee
   * @param role Role to grant
   * @returns The invite link
   */
  const linkFor = async (
    email: string,
    role: "admin" | "member" = "member",
  ): Promise<string> => {
    await as(owner, () => owner.cli.org.invite(email, role));

    return owner.output.at(-2) ?? "";
  };

  /**
   * ### joinByLink
   *
   * A new member joins from an invite link and the owner's next listing certifies them.
   *
   * @param name Short name
   * @returns The certified member
   */
  const joinByLink = async (name: string): Promise<Member> => {
    const joining = member(name);
    const link = await linkFor(joining.email);

    joining.secrets.push(joining.password, joining.password);
    await joining.cli.account.signupWithLink(link, name);
    await as(owner, () => owner.cli.org.members());

    return joining;
  };

  /**
   * ### joinByToken
   *
   * A new member types the invite token in, pins the owner after comparing, and the owner
   * certifies them by fingerprint.
   *
   * @param name Short name
   * @param role Role to grant
   * @returns The certified member
   */
  const joinByToken = async (
    name: string,
    role: "admin" | "member" = "member",
  ): Promise<Member> => {
    const joining = member(name);
    const token = parseInviteLink(await linkFor(joining.email, role))?.token;

    await joining.cli.account.init(serverUrl);
    joining.secrets.push(joining.password, joining.password);
    joining.answers.push("yes");
    await joining.cli.account.signup(token ?? "", joining.email, name);

    const fingerprint = (
      joining.output.find((line) => line.startsWith("Your fingerprint: ")) ?? ""
    ).slice("Your fingerprint: ".length);

    await as(owner, () => owner.cli.org.certify(joining.email, fingerprint));

    return joining;
  };

  /**
   * ### printedBy
   *
   * Runs a command and returns only the lines it printed.
   *
   * @param who Member whose output to read
   * @param command Command to run
   * @returns New output lines
   */
  const printedBy = async (
    who: Pick<Member, "output">,
    command: () => Promise<unknown>,
  ): Promise<Array<string>> => {
    const before = who.output.length;

    await command();

    return who.output.slice(before);
  };

  beforeAll(async () => {
    db = new PgliteDatabase();
    await migrate(db);
    app = buildApp({
      store: new SqlStore(db),
      serverSecret: new Uint8Array(32).fill(3),
      now: () => new Date(now),
    });
    serverUrl = await app.listen({ host: "127.0.0.1", port: 0 });
    workDir = await mkdtemp(join(tmpdir(), "keymember-cli-"));

    owner = member("owner");
    await owner.cli.account.init(serverUrl);
    owner.secrets.push(owner.password, owner.password);
    await owner.cli.account.bootstrap("Example", owner.email, "Owner");

    bob = await joinByLink("bob");
    await as(owner, () =>
      owner.cli.vaults.create("Infra", [`${bob.email}:edit`]),
    );
    owner.secrets.push(owner.password, "db-secret-123");
    await owner.cli.items.add("Infra", {
      title: "DB prod",
      urls: [],
      username: "app",
      generate: false,
    });
  });

  afterAll(async () => {
    await app.close();
    await db.close();
    await rm(workDir, { recursive: true, force: true });
  });

  it("bootstraps the organisation with a private config and an Emergency Kit", async () => {
    const kit = await readFile(
      join(workDir, "keymember-emergency-kit-owner@example.com.pdf"),
    );
    const configMode =
      (await stat(join(workDir, "owner", "config.json"))).mode & 0o777;

    expect(
      owner.output.some((line) => line.startsWith("Secret Key: K1-")),
    ).toBe(true);
    expect(kit.subarray(0, 5).toString()).toBe("%PDF-");
    expect(configMode).toBe(0o600);
  });

  it("lets a member join by link and get certified without a fingerprint", async () => {
    const carol = await joinByLink("carol");

    expect(carol.output.at(-1)).toMatch(/^Joined\./);
    expect(owner.output).toContain(
      "Certified carol@example.com, who joined by your link",
    );

    const lines = await printedBy(carol, () =>
      as(carol, () => carol.cli.org.members()),
    );

    expect(
      lines.find((line) => line.startsWith("carol@example.com")),
    ).toContain("verified");
  });

  it("still lets a member who typed the token in pin the owner and be certified by fingerprint", async () => {
    const dana = await joinByToken("dana");

    expect(dana.output).toContain("Owner key pinned");
    expect(owner.output.at(-1)).toBe("Certified dana@example.com");
  });

  it("injects secrets into a child process and reports its exit code", async () => {
    const read = await printedBy(bob, () =>
      as(bob, () => bob.cli.items.get("DB prod", "password")),
    );

    expect(read).toEqual(["db-secret-123"]);

    const exitCode = await as(bob, () =>
      bob.cli.items.run(
        ["DB_PASSWORD=DB prod.password", "DB_USER=DB prod.username"],
        [
          process.execPath,
          "-e",
          "process.exit(process.env.DB_PASSWORD === 'db-secret-123' && process.env.DB_USER === 'app' ? 7 : 1)",
        ],
      ),
    );

    expect(exitCode).toBe(7);

    // A child killed by a signal exits like it would in a shell: 128 plus the signal number
    const killed = await as(bob, () =>
      bob.cli.items.run(
        ["DB_PASSWORD=DB prod.password"],
        [process.execPath, "-e", "process.kill(process.pid, 'SIGTERM')"],
      ),
    );

    expect(killed).toBe(143);
  });

  it("still runs the command when logging out fails, and only warns", async () => {
    // Bob's own config, reached through a transport that cannot log out
    const flaky = {
      ...member("bob", (url) => {
        const transport = fetchTransport(url);

        return (request) =>
          request.path === "/api/auth/logout"
            ? Promise.reject(new Error("network down"))
            : transport(request);
      }),
      password: bob.password,
    };
    const exitCode = await as(flaky, () =>
      flaky.cli.items.run(
        ["DB_PASSWORD=DB prod.password"],
        [
          process.execPath,
          "-e",
          "process.exit(process.env.DB_PASSWORD === 'db-secret-123' ? 0 : 1)",
        ],
      ),
    );

    expect(exitCode).toBe(0);
    expect(flaky.warnings).toEqual([
      expect.stringMatching(/^Could not log out \(network down\)/),
    ]);
  });

  it("reads, deletes and resolves items by id, exact title, then any case", async () => {
    for (const password of ["twin-1", "twin-2"]) {
      owner.secrets.push(owner.password, password);
      await owner.cli.items.add("Infra", {
        title: "Twin",
        urls: [],
        generate: false,
      });
    }

    await expect(as(owner, () => owner.cli.items.get("Twin"))).rejects.toThrow(
      /"Twin" matches several items \(.+\); use the id/,
    );
    await expect(
      as(owner, () => owner.cli.items.get("No such thing")),
    ).rejects.toThrow('No item "No such thing"');

    // A title typed in another case still finds a unique item
    const json = await printedBy(owner, () =>
      as(owner, () => owner.cli.items.get("db PROD")),
    );

    expect(JSON.parse(json.join("\n"))).toMatchObject({
      details: { password: "db-secret-123" },
    });

    const listed = await printedBy(owner, () =>
      as(owner, () => owner.cli.items.list("Infra")),
    );
    const twins = listed
      .filter((line) => line.includes("\tTwin\t"))
      .map((line) => line.split("\t")[0] ?? "");

    expect(twins).toHaveLength(2);

    await as(owner, () => owner.cli.items.delete(twins[0] ?? ""));
    expect(owner.output.at(-1)).toBe("Deleted");

    const remaining = await printedBy(owner, () =>
      as(owner, () => owner.cli.items.get("Twin", "password")),
    );

    expect(remaining).toHaveLength(1);
  });

  it("imports a Chrome CSV export into a vault", async () => {
    const file = join(workDir, "chrome.csv");

    await writeFile(
      file,
      [
        "name,url,username,password,note",
        "Mail,https://mail.example.com,me,mail-pass,",
        "Wiki,https://wiki.example.com,me,wiki-pass,team wiki",
      ].join("\n"),
    );
    await as(owner, () => owner.cli.vaults.create("Imports", []));

    const printed = await printedBy(owner, () =>
      as(owner, () => owner.cli.items.importFile(file, "Imports")),
    );

    expect(printed[0]).toBe("Imported 2 item(s)");

    const read = await printedBy(owner, () =>
      as(owner, () => owner.cli.items.get("Wiki", "password")),
    );

    expect(read).toEqual(["wiki-pass"]);

    // Without a recognisable extension the format must be named
    const unnamed = join(workDir, "export.txt");

    await writeFile(unnamed, "name,url\n");
    await expect(
      owner.cli.items.importFile(unnamed, "Imports"),
    ).rejects.toThrow("pass --format");
  });

  it("creates a group, shares a vault with it, removes a member and deletes it", async () => {
    await as(owner, () => owner.cli.groups.create("개발", [bob.email]));
    await as(owner, () => owner.cli.vaults.create("배포", [], ["개발:view"]));

    const listed = await printedBy(owner, () =>
      as(owner, () => owner.cli.groups.list()),
    );

    expect(listed).toContainEqual(
      expect.stringMatching(/\tv1\tok\t개발\tbob@example\.com$/),
    );

    const bobsVaults = (): Promise<Array<string>> =>
      printedBy(bob, () => as(bob, () => bob.cli.vaults.list()));

    expect(await bobsVaults()).toContainEqual(
      expect.stringMatching(/\tview\t배포$/),
    );

    await as(owner, () => owner.cli.groups.remove("개발", bob.email));

    // Bob keeps Infra through his own grant and loses what only the group gave him
    const after = await bobsVaults();

    expect(after.some((line) => line.endsWith("\t배포"))).toBe(false);
    expect(after.some((line) => line.endsWith("\tInfra"))).toBe(true);

    await as(owner, () => owner.cli.groups.delete("개발"));
    expect(owner.output.at(-1)).toBe("Deleted group 개발");
    await expect(
      as(owner, () => owner.cli.groups.delete("개발")),
    ).rejects.toThrow('No group "개발"');
  });

  it("prints a share link that opens without an account", async () => {
    await as(owner, () =>
      owner.cli.items.share("DB prod", {
        fields: ["password"],
        hours: 1,
        views: 1,
        withPassphrase: false,
      }),
    );

    const url = owner.output.at(-2) ?? "";
    const link = parseShareLink(url);

    expect(url.startsWith(`${serverUrl}/#/share/`)).toBe(true);
    expect(link).toBeDefined();

    const opened = await openShareLink(
      fetchTransport(serverUrl),
      link ?? { shareId: "", secret: "", needsPassphrase: false },
    );

    expect(opened.snapshot.password).toBe("db-secret-123");
    expect(opened.snapshot.username).toBeUndefined();
  });

  it("adds an account to a new device from its Secret Key, with the saved roots", async () => {
    const secretKey = (
      bob.output.find((line) => line.startsWith("Secret Key: ")) ?? ""
    ).slice("Secret Key: ".length);
    const laptop = { ...member("bob-laptop"), password: bob.password };

    await laptop.cli.account.init(serverUrl);
    await as(laptop, () => laptop.cli.account.addDevice(bob.email, secretKey));

    expect(laptop.output.at(-1)).toBe(
      "This device trusts your organisation's keys",
    );

    const fingerprints = await printedBy(laptop, () =>
      as(laptop, () => laptop.cli.account.fingerprint()),
    );
    const original = await printedBy(bob, () =>
      as(bob, () => bob.cli.account.fingerprint()),
    );

    expect(fingerprints).toEqual(original);
    await expect(
      laptop.cli.account.addDevice(bob.email, "not a key"),
    ).rejects.toThrow("That is not a valid Secret Key");
  });

  it("enables two-factor login and then asks for a code at every login", async () => {
    const erin = await joinByLink("erin");
    const step = (): number => Math.floor(now / 30_000);
    const seed = (): Uint8Array =>
      base32Decode(
        /\(secret: ([A-Z2-7]+)\)/.exec(
          erin.output.find((line) => line.includes("(secret: ")) ?? "",
        )?.[1] ?? "",
      );

    // The code is worked out when asked for, from the secret the command just printed
    erin.answers.push(() => codeForStep(seed(), step()));
    await as(erin, () => erin.cli.account.setupTotp());
    expect(erin.output.at(-1)).toBe("Two-factor login enabled");

    // A used code cannot log in again, so the next login comes a step later
    now += 30_000;
    erin.answers.push(() => codeForStep(seed(), step()));

    const members = await printedBy(erin, () =>
      as(erin, () => erin.cli.org.members()),
    );

    expect(members.some((line) => line.startsWith("erin@example.com"))).toBe(
      true,
    );
    expect(erin.answers).toEqual([]);
  });

  it("switches login policies and shows the audit log", async () => {
    // An admin who uses two-factor login herself, so the policy cannot lock her out
    const hana = await joinByToken("hana", "admin");
    const step = (): number => Math.floor(now / 30_000);
    const code = (): string =>
      codeForStep(
        base32Decode(
          /\(secret: ([A-Z2-7]+)\)/.exec(
            hana.output.find((line) => line.includes("(secret: ")) ?? "",
          )?.[1] ?? "",
        ),
        step(),
      );
    const asHana = <T>(command: () => Promise<T>): Promise<T> => {
      // Every login asks for a fresh code, a step after the last one used
      now += 30_000;
      hana.answers.push(code);

      return as(hana, command);
    };

    hana.answers.push(code);
    await as(hana, () => hana.cli.account.setupTotp());
    await asHana(() => hana.cli.org.setPolicy({ requireTotp: true }));
    expect(hana.output.at(-1)).toBe("Two-factor login is now required");

    // A member without an authenticator is told to set one up first
    await expect(as(bob, () => bob.cli.vaults.list())).rejects.toMatchObject({
      code: "totp_enrollment_required",
    });

    await asHana(() => hana.cli.org.setPolicy({ requireTotp: false }));
    expect(hana.output.at(-1)).toBe("Two-factor login is now optional");

    const events = await printedBy(hana, () =>
      asHana(() => hana.cli.org.audit(50)),
    );

    expect(
      events.filter((line) => line.includes("\torg.policy_updated\t")),
    ).toHaveLength(2);
    expect(events.length).toBeLessThanOrEqual(50);
  });

  it("recovers a member with two admins, and cancels a second recovery", async () => {
    const alice = await joinByToken("alice", "admin");
    const frank = await joinByLink("frank");

    await as(owner, () =>
      owner.cli.vaults.create("Recovery test", [`${frank.email}:edit`]),
    );
    // An admin certified by the requester only just now could be the requester's second identity
    now += 8 * DAY_MS;

    await as(owner, () => owner.cli.recovery.request(frank.email));

    const recoveryId = owner.output.at(-2) ?? "";

    await as(alice, () => alice.cli.recovery.approve(recoveryId));

    const token = alice.output.at(-2) ?? "";
    const newPassword = "frank-new-password-99";

    frank.secrets.push(newPassword, newPassword);
    await frank.cli.account.recover(token);

    const fingerprint = (
      frank.output.find((line) => line.startsWith("Your new fingerprint: ")) ??
      ""
    ).slice("Your new fingerprint: ".length);

    await as(owner, () => owner.cli.org.certify(frank.email, fingerprint));
    await as(owner, () => owner.cli.recovery.complete(recoveryId));
    expect(owner.output.at(-1)).toMatch(/^Recovery completed; 1 vault\(s\)/);

    const recovered = { ...frank, password: newPassword };
    const vaults = await printedBy(recovered, () =>
      as(recovered, () => recovered.cli.vaults.list()),
    );

    expect(vaults.some((line) => line.endsWith("\tRecovery test"))).toBe(true);

    // A second recovery can be cancelled before anyone approves it
    await as(owner, () => owner.cli.recovery.request(bob.email));

    const second = owner.output.at(-2) ?? "";

    await as(owner, () => owner.cli.recovery.cancel(second));
    expect(owner.output.at(-1)).toBe("Recovery cancelled");

    const listed = await printedBy(owner, () =>
      as(owner, () => owner.cli.recovery.list()),
    );

    expect(listed).toContainEqual(
      expect.stringMatching(new RegExp(`^${recoveryId}\\tcompleted\\t`)),
    );
    expect(listed).toContainEqual(
      expect.stringMatching(new RegExp(`^${second}\\tcancelled\\t`)),
    );
  });

  it("offboards a member and reports what it rotated", async () => {
    const gina = await joinByLink("gina");

    await as(owner, () =>
      owner.cli.vaults.create("Offboarding test", [`${gina.email}:view`]),
    );
    await as(owner, () => owner.cli.org.offboard(gina.email));

    expect(owner.output.at(-1)).toMatch(
      /^Suspended gina@example\.com; rotated 0 group key\(s\) and 1 vault key\(s\)$/,
    );
    await expect(as(gina, () => gina.cli.vaults.list())).rejects.toMatchObject({
      status: 403,
    });
  });
});

describe("CLI helpers", () => {
  it("splits env mappings on the last dot so titles may contain dots", () => {
    expect(parseEnvMapping("API_KEY=api.example.com.password")).toEqual({
      name: "API_KEY",
      item: "api.example.com",
      field: "password",
    });
    expect(() => parseEnvMapping("1BAD=x.password")).toThrow();
    expect(() => parseEnvMapping("NAME=nofield")).toThrow();
  });

  it("reads built-in and custom fields", () => {
    const item = {
      overview: { urls: ["https://example.com"] },
      details: {
        password: "p",
        fields: [{ label: "PIN", value: "1234", concealed: true }],
        passwordHistory: [],
      },
    };

    expect(readField(item, "password")).toBe("p");
    expect(readField(item, "PIN")).toBe("1234");
    expect(readField(item, "url")).toBe("https://example.com");
    expect(() => readField(item, "totp")).toThrow(/no "totp"/);
  });

  it("puts the Secret Key but never a password into the add-device QR", () => {
    const uri = addDeviceUri({
      serverUrl: "https://keymember.example.com",
      email: "a@b.c",
      secretKey: generateSecretKey(),
      createdAt: new Date(),
    });

    expect(uri).toMatch(
      /^keymember:\/\/add-device\?server=.+&email=.+&key=K1-/,
    );
    expect(uri).not.toMatch(/password/i);
  });
});
