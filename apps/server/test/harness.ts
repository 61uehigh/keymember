import {
  bootstrapOrganization,
  logIn,
  Session,
  signUp,
} from "@keymember/client";
import type { SessionSnapshot, Transport } from "@keymember/client";
import type { SecretKey } from "@keymember/core";
import type { FastifyInstance } from "fastify";
import { afterAll, beforeAll } from "vitest";

import { Firestore } from "@google-cloud/firestore";

import {
  buildApp,
  FirestoreStore,
  migrate,
  PgliteDatabase,
  SqlStore,
} from "@keymember/server";
import type { AppOptions, Store } from "@keymember/server";

import { firestoreTables, sqlTables } from "./tables.js";
import type { Tables } from "./tables.js";

/**
 * ### TestServer
 *
 * An in-process server with a controllable clock, on an in-memory PGlite database, or on the
 * Firestore emulator when `KEYMEMBER_TEST_STORE=firestore`.
 */
export interface TestServer {
  /**
   * ### app
   *
   * Fastify instance; requests go through `inject`, no port is opened.
   */
  readonly app: FastifyInstance;

  /**
   * ### tables
   *
   * Raw access to what the server stores, for assertions and for playing a hostile server.
   */
  readonly tables: Tables;

  /**
   * ### transport
   *
   * Client transport bound to the in-process server.
   */
  readonly transport: Transport;

  /**
   * ### clock
   *
   * Mutable clock read by the server; advance `clock.now` to move time.
   */
  readonly clock: { now: Date };

  /**
   * ### roots
   *
   * Pinned owner key for this test organisation; {@link loginAs} gives it to every session.
   * Tests add the owner's key right after initialising the organisation.
   */
  readonly roots: Map<string, Uint8Array>;

  /**
   * ### image
   *
   * Captures the database and roots, for {@link startTestServer} to start another server from.
   */
  image(): Promise<ServerImage>;

  /**
   * ### close
   *
   * Shuts the app and database down.
   */
  close(): Promise<void>;
}

/**
 * ### ServerImage
 *
 * A test server's database and pinned roots at one moment.
 */
export interface ServerImage {
  readonly data: StoreImage;
  readonly roots: ReadonlyMap<string, Uint8Array>;
}

/**
 * ### startTestServer
 *
 * Starts a server on a fresh, migrated database, or on a copy of an earlier server's.
 *
 * @param options Extra app options, such as an identity provider
 * @param from Image to start from instead of an empty database
 * @returns The running test server
 */
export async function startTestServer(
  options: Pick<AppOptions, "sso" | "ssoFetch" | "bootstrapToken"> = {},
  from?: ServerImage,
): Promise<TestServer> {
  const backend =
    process.env.KEYMEMBER_TEST_STORE === "firestore"
      ? await firestoreBackend(from?.data)
      : await sqlBackend(from?.data);
  const roots = new Map(from?.roots);

  const clock = { now: new Date("2026-10-22T09:00:00Z") };
  const app = buildApp({
    store: backend.store,
    serverSecret: new Uint8Array(32).fill(7),
    now: () => clock.now,
    ...options,
  });
  const transport: Transport = async (request) => {
    const response = await app.inject({
      method: request.method,
      url: request.path,
      headers: {
        ...(request.token === undefined
          ? {}
          : { authorization: `Bearer ${request.token}` }),
        ...(request.body === undefined
          ? {}
          : { "content-type": "application/json" }),
      },
      ...(request.body === undefined
        ? {}
        : { payload: JSON.stringify(request.body) }),
    });

    return {
      status: response.statusCode,
      body:
        response.body.length === 0
          ? undefined
          : (JSON.parse(response.body) as unknown),
    };
  };

  return {
    app,
    tables: backend.tables,
    transport,
    clock,
    roots,
    image: async () => ({ data: await backend.image(), roots: new Map(roots) }),
    close: async () => {
      await app.close();
      await backend.close();
    },
  };
}

/**
 * ### StoreImage
 *
 * A copy of one test server's data: a PGlite dump, or the id of a Firestore emulator project
 * holding a copy.
 */
type StoreImage = Blob | string;

/**
 * ### Backend
 *
 * The store a test server runs on, with raw access and a way to copy it.
 */
interface Backend {
  readonly store: Store;
  readonly tables: Tables;
  image(): Promise<StoreImage>;
  close(): Promise<void>;
}

/**
 * ### sqlBackend
 *
 * In-memory PGlite, migrated, or loaded from an earlier dump.
 *
 * @param from Dump to start from
 * @returns The backend
 */
async function sqlBackend(from: StoreImage | undefined): Promise<Backend> {
  if (typeof from === "string") {
    throw new Error("A Firestore image cannot start a PGlite server");
  }

  const db = new PgliteDatabase(from);

  if (from === undefined) {
    await migrate(db);
  }

  return {
    store: new SqlStore(db),
    tables: sqlTables(db),
    image: () => db.dump(),
    close: () => db.close(),
  };
}

/**
 * ### firestoreBackend
 *
 * A fresh project on the Firestore emulator (`FIRESTORE_EMULATOR_HOST`), empty or holding a
 * copy of an earlier image. Each server gets its own project, so test files can run in parallel.
 *
 * @param from Project id of an image to copy from
 * @returns The backend
 */
async function firestoreBackend(
  from: StoreImage | undefined,
): Promise<Backend> {
  if (from instanceof Blob) {
    throw new Error("A PGlite dump cannot start a Firestore server");
  }

  const newProjectId = (): string =>
    `demo-keymember-${crypto.randomUUID().slice(0, 8)}`;
  const projectId = newProjectId();
  const db = new Firestore({ projectId });

  if (from !== undefined) {
    const source = new Firestore({ projectId: from });

    await copyProject(source, db);
    await source.terminate();
  }

  return {
    store: new FirestoreStore(db),
    tables: firestoreTables(db),
    image: async () => {
      const projectId = newProjectId();
      const copy = new Firestore({ projectId });

      await copyProject(db, copy);
      await copy.terminate();

      return projectId;
    },
    close: async () => {
      await db.terminate();
      await clearProject(projectId);
    },
  };
}

/**
 * ### clearProject
 *
 * Deletes every document of an emulator project, so test runs do not pile up data in the
 * emulator's memory.
 *
 * @param projectId Emulator project
 */
async function clearProject(projectId: string): Promise<void> {
  const host = process.env.FIRESTORE_EMULATOR_HOST ?? "";

  await fetch(
    `http://${host}/emulator/v1/projects/${projectId}/databases/(default)/documents`,
    { method: "DELETE" },
  );
}

/**
 * ### copyProject
 *
 * Copies every document of one emulator project into another.
 *
 * @param source Project to copy from
 * @param target Project to copy into
 */
async function copyProject(
  source: Firestore,
  target: Firestore,
): Promise<void> {
  const writer = target.bulkWriter();

  for (const collection of await source.listCollections()) {
    for (const document of (await collection.get()).docs) {
      void writer.set(
        target.collection(collection.id).doc(document.id),
        document.data(),
      );
    }
  }

  await writer.close();
}

/**
 * ### loginAs
 *
 * Logs in with fixed test device details.
 *
 * @param server Test server
 * @param email Account email
 * @param password Account password
 * @param secretKey Account Secret Key
 * @param totp Two-factor code, when enabled
 * @returns The unlocked session
 */
export async function loginAs(
  server: TestServer,
  email: string,
  password: string,
  secretKey: SecretKey,
  totp?: string,
): Promise<Session> {
  const session = await logIn(server.transport, {
    email,
    password,
    secretKey,
    deviceId: crypto.randomUUID(),
    deviceName: "vitest",
    ...(totp === undefined ? {} : { totp }),
  });

  session.setRoots(server.roots);

  return session;
}

/**
 * ### Member
 *
 * A test account with its credentials and an unlocked session.
 */
export interface Member {
  readonly session: Session;
  readonly email: string;
  readonly password: string;
  readonly secretKey: SecretKey;
}

/**
 * ### bootstrapTeam
 *
 * Creates the organisation and its owner, initialises it, and pins the owner as the root of
 * the server and of the owner's session.
 *
 * @param server Test server
 * @param email Owner's email
 * @returns The owner
 */
export async function bootstrapTeam(
  server: TestServer,
  email = "owner@example.com",
  bootstrapToken?: string,
): Promise<Member> {
  const password = "owner-password";
  const account = await bootstrapOrganization(
    server.transport,
    "Example",
    { email, name: "Owner", password },
    bootstrapToken,
  );
  const session = await loginAs(server, email, password, account.secretKey);

  await session.orgAdmin().initializeOrganization();
  server.roots.set(session.user.id, session.signingPublicKey);
  session.setRoots(server.roots);

  return { session, email, password, secretKey: account.secretKey };
}

/**
 * ### joinTeam
 *
 * Invites, signs up, logs in and certifies a member. The password is `<name>-password`.
 *
 * @param server Test server
 * @param admin Admin who invites and certifies
 * @param email New member's email
 * @param role Role to invite with
 * @returns The new member
 */
export async function joinTeam(
  server: TestServer,
  admin: Session,
  email: string,
  role: "admin" | "member" = "member",
): Promise<Member> {
  const name = email.split("@")[0] ?? email;
  const password = `${name}-password`;
  const { inviteToken } = await admin.orgAdmin().invite(email, role);
  const account = await signUp(server.transport, inviteToken, {
    email,
    name,
    password,
  });
  const session = await loginAs(server, email, password, account.secretKey);

  await admin.orgAdmin().certify(session.user.id, session.fingerprint);

  return { session, email, password, secretKey: account.secretKey };
}

/**
 * ### SessionImage
 *
 * Where a captured fixture held a session.
 */
class SessionImage {
  readonly snapshot: SessionSnapshot;

  /**
   * ### constructor
   *
   * @param snapshot The session's snapshot
   */
  constructor(snapshot: SessionSnapshot) {
    this.snapshot = snapshot;
  }
}

/**
 * ### capture
 *
 * Replaces every session in a fixture with its snapshot.
 *
 * @param value Fixture value
 * @returns The value with sessions captured
 */
function capture(value: unknown): unknown {
  if (value instanceof Session) {
    return new SessionImage(value.toSnapshot());
  }

  if (typeof value === "function") {
    throw new Error(
      "A server fixture cannot hold functions; build them after restoring",
    );
  }

  if (Array.isArray(value)) {
    return value.map(capture);
  }

  if (
    value !== null &&
    typeof value === "object" &&
    !ArrayBuffer.isView(value) &&
    !(value instanceof Map)
  ) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, capture(entry)]),
    );
  }

  return value;
}

/**
 * ### revive
 *
 * Turns captured sessions back into sessions on a server and refreshes their caches.
 *
 * @param value Captured value
 * @param server Server the sessions talk to
 * @param sessions Collects the revived sessions
 * @returns The revived value
 */
function revive(
  value: unknown,
  server: TestServer,
  sessions: Array<Session>,
): unknown {
  if (value instanceof SessionImage) {
    const session = Session.fromSnapshot(server.transport, value.snapshot);

    session.setRoots(server.roots);
    sessions.push(session);

    return session;
  }

  if (Array.isArray(value)) {
    return value.map((entry) => revive(entry, server, sessions));
  }

  if (
    value !== null &&
    typeof value === "object" &&
    !ArrayBuffer.isView(value) &&
    !(value instanceof Map)
  ) {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [
        key,
        revive(entry, server, sessions),
      ]),
    );
  }

  return value;
}

/**
 * ### serverFixture
 *
 * Builds a fixture once per test file and hands every test its own server started from a
 * copy of that state, with the fixture's sessions restored onto it. Setting up a team derives
 * Argon2id for each new account, which made per-test setup the slowest part of the suite.
 *
 * Call it at the top of a `describe`; it registers the hooks that build and drop the image.
 *
 * @param build Sets up the server and returns plain data and sessions (no functions)
 * @param options App options for every server, such as an identity provider
 * @returns `restore`, which starts a fresh server and fixture for one test
 */
export function serverFixture<T>(
  build: (server: TestServer) => Promise<T>,
  options: () => Pick<AppOptions, "sso" | "ssoFetch"> = () => ({}),
): { restore(): Promise<{ server: TestServer; fixture: T }> } {
  let image: ServerImage | undefined;
  let captured: unknown;

  beforeAll(async () => {
    const server = await startTestServer(options());

    try {
      captured = capture(await build(server));
      image = await server.image();
    } finally {
      await server.close();
    }
  });

  afterAll(async () => {
    // A Firestore image is a whole emulator project of its own
    if (typeof image?.data === "string") {
      await clearProject(image.data);
    }

    image = undefined;
  });

  return {
    restore: async () => {
      if (image === undefined) {
        throw new Error("The fixture is not built yet");
      }

      const server = await startTestServer(options(), image);
      const sessions: Array<Session> = [];
      const fixture = revive(captured, server, sessions) as T;

      // A snapshot carries keys and tokens but not the synced vaults and items
      await Promise.all(sessions.map((session) => session.sync()));

      return { server, fixture };
    },
  };
}

/**
 * ### rewriting
 *
 * Wraps a transport so a test can tamper with requests or responses, as a hostile server would.
 *
 * @param inner Transport to wrap
 * @param rewrite Hooks that may replace a request body or response body
 * @returns The tampering transport
 */
export function rewriting(
  inner: Transport,
  rewrite: {
    request?: (path: string, body: unknown) => unknown;
    response?: (path: string, body: unknown) => unknown;
  },
): Transport {
  return async (request) => {
    const body =
      rewrite.request === undefined
        ? request.body
        : rewrite.request(request.path, request.body);
    const response = await inner({
      ...request,
      ...(body === undefined ? {} : { body }),
    });

    return rewrite.response === undefined
      ? response
      : { ...response, body: rewrite.response(request.path, response.body) };
  };
}

/**
 * ### base32Decode
 *
 * Decodes an RFC 4648 base32 secret as an authenticator app would.
 *
 * @param text Base32 text without padding
 * @returns The decoded secret
 */
export function base32Decode(text: string): Uint8Array {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const output: Array<number> = [];
  let buffer = 0;
  let bits = 0;

  for (const char of text.replace(/=+$/, "")) {
    buffer = (buffer << 5) | alphabet.indexOf(char);
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      output.push((buffer >> bits) & 0xff);
    }
  }

  return Uint8Array.from(output);
}
