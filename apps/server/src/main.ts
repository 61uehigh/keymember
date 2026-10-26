import { resolve } from "node:path";

import { Firestore } from "@google-cloud/firestore";

import { fromBase64Url, randomBytes, toBase64Url } from "@keymember/core";

import { buildApp } from "./buildApp.js";
import { migrate, PgDatabase, PgliteDatabase } from "./db/Database.js";
import type { Database } from "./db/Database.js";
import { FirestoreStore } from "./firestore/FirestoreStore.js";
import { startMaintenance } from "./services/maintenance.js";
import { SqlStore } from "./repositories/pg/SqlStore.js";
import type { Store } from "./repositories/Store.js";
import type { OidcConfig } from "./services/OidcClient.js";

/**
 * ### readServerSecret
 *
 * Reads `KEYMEMBER_SERVER_SECRET` (base64url, at least 32 bytes) and exits with a clear
 * message when it is missing, so the server never starts with a guessable secret.
 *
 * @returns The decoded secret
 */
function readServerSecret(): Uint8Array {
  const raw = process.env.KEYMEMBER_SERVER_SECRET;
  const decoded = raw === undefined ? undefined : fromBase64Url(raw);

  if (decoded === undefined || decoded.length < 32) {
    throw new Error(
      "KEYMEMBER_SERVER_SECRET must be set to at least 32 random bytes in base64url (e.g. `openssl rand -base64 32 | tr '+/' '-_' | tr -d '='`)",
    );
  }

  return decoded;
}

/**
 * ### readTrustProxy
 *
 * Reads `KEYMEMBER_TRUST_PROXY`: a number of proxy hops, `true`, or unset for none.
 *
 * @returns The Fastify `trustProxy` setting
 */
function readTrustProxy(): boolean | number {
  const raw = process.env.KEYMEMBER_TRUST_PROXY ?? "";

  if (/^\d+$/.test(raw)) {
    return Number(raw);
  }

  return raw === "true";
}

/**
 * ### OpenedStore
 *
 * The store the server runs on, and how to release it at shutdown.
 */
interface OpenedStore {
  readonly store: Store;
  close(): Promise<void>;
}

/**
 * ### openStore
 *
 * Opens the store `KEYMEMBER_STORE` names:
 *
 * - `firestore`: Firestore in the Google Cloud project the server runs in (on Cloud Run, its
 *   service account; elsewhere, `GOOGLE_CLOUD_PROJECT` and Application Default Credentials).
 *   `KEYMEMBER_FIRESTORE_DATABASE` picks a database other than `(default)`.
 * - `sql` (the default): PostgreSQL from `DATABASE_URL`, or an embedded PGlite database kept in
 *   the `KEYMEMBER_PGLITE_DIR` directory. Migrations run before the server starts.
 *
 * @returns The open store
 */
async function openStore(): Promise<OpenedStore> {
  const kind = process.env.KEYMEMBER_STORE ?? "sql";

  if (kind === "firestore") {
    const databaseId = process.env.KEYMEMBER_FIRESTORE_DATABASE ?? "";
    const firestore = new Firestore(databaseId === "" ? {} : { databaseId });

    return {
      store: new FirestoreStore(firestore),
      close: () => firestore.terminate(),
    };
  }

  if (kind !== "sql") {
    throw new Error('KEYMEMBER_STORE must be "sql" or "firestore"');
  }

  const db = openDatabase();

  await migrate(db);

  return { store: new SqlStore(db), close: () => db.close() };
}

/**
 * ### openDatabase
 *
 * Opens PostgreSQL from `DATABASE_URL`, or an embedded PGlite database in `KEYMEMBER_PGLITE_DIR`.
 *
 * @returns An open database
 */
function openDatabase(): Database {
  const url = process.env.DATABASE_URL;

  if (url !== undefined && url.length > 0) {
    return new PgDatabase(url);
  }

  const dir = process.env.KEYMEMBER_PGLITE_DIR;

  if (dir !== undefined && dir.length > 0) {
    return new PgliteDatabase(dir);
  }

  throw new Error(
    "Set DATABASE_URL, KEYMEMBER_PGLITE_DIR, or KEYMEMBER_STORE=firestore",
  );
}

/**
 * ### readSsoConfig
 *
 * Reads the identity provider from `KEYMEMBER_OIDC_*` and `KEYMEMBER_PUBLIC_URL`. All of issuer,
 * client id, client secret and public URL must be set together, or none of them.
 *
 * @returns The provider configuration, or `undefined` when SSO is not configured
 */
function readSsoConfig(): OidcConfig | undefined {
  const issuer = process.env.KEYMEMBER_OIDC_ISSUER ?? "";
  const clientId = process.env.KEYMEMBER_OIDC_CLIENT_ID ?? "";
  const clientSecret = process.env.KEYMEMBER_OIDC_CLIENT_SECRET ?? "";
  const publicUrl = process.env.KEYMEMBER_PUBLIC_URL ?? "";
  const hostedDomain = process.env.KEYMEMBER_OIDC_HOSTED_DOMAIN ?? "";
  const values = [issuer, clientId, clientSecret, publicUrl];

  if (values.every((value) => value === "")) {
    return undefined;
  }

  if (values.some((value) => value === "")) {
    console.error(
      "Set KEYMEMBER_OIDC_ISSUER, KEYMEMBER_OIDC_CLIENT_ID, KEYMEMBER_OIDC_CLIENT_SECRET and KEYMEMBER_PUBLIC_URL together",
    );
    process.exit(1);
  }

  return {
    issuer,
    clientId,
    clientSecret,
    redirectUri: new URL("/api/auth/sso/callback", publicUrl).toString(),
    ...(hostedDomain === "" ? {} : { hostedDomain }),
  };
}

/**
 * ### readBootstrapToken
 *
 * The token the first owner must present: `KEYMEMBER_BOOTSTRAP_TOKEN`, or a random one.
 *
 * @returns The token, and whether it was made up here (and so must be shown to the operator)
 */
function readBootstrapToken(): { token: string; generated: boolean } {
  const configured = process.env.KEYMEMBER_BOOTSTRAP_TOKEN ?? "";

  if (configured !== "") {
    return { token: configured, generated: false };
  }

  return { token: toBase64Url(randomBytes(24)), generated: true };
}

const opened = await openStore();
const bootstrap = readBootstrapToken();

const app = buildApp({
  store: opened.store,
  serverSecret: readServerSecret(),
  trustProxy: readTrustProxy(),
  ...(process.env.KEYMEMBER_WEB_DIR === undefined ||
  process.env.KEYMEMBER_WEB_DIR === ""
    ? {}
    : { webRoot: resolve(process.env.KEYMEMBER_WEB_DIR) }),
  logger: true,
  sso: readSsoConfig(),
  bootstrapToken: bootstrap.token,
});

app.log.info(
  "Login rate limits are kept in this process's memory; with several instances each counts on its own",
);

if (!(await opened.store.repositories().organizations.isBootstrapped())) {
  app.log.info(
    bootstrap.generated
      ? `No organisation yet. Bootstrap token for creating it: ${bootstrap.token}`
      : "No organisation yet. Creating it needs the token in KEYMEMBER_BOOTSTRAP_TOKEN",
  );
}

const stopMaintenance = startMaintenance(opened.store, (error) => {
  app.log.error(error, "Removing expired records failed");
});

/**
 * ### SHUTDOWN_TIMEOUT_MS
 *
 * How long a shutdown may take before the process exits anyway: within Cloud Run's 10 seconds
 * after SIGTERM, and well within the 30 seconds compose allows.
 */
const SHUTDOWN_TIMEOUT_MS = 8_000;

let stopping = false;

/**
 * ### shutdown
 *
 * Stops taking requests, then closes the store so the database is left consistent, and exits.
 * The store is closed even when closing the HTTP server fails; a second signal exits at once.
 */
const shutdown = async (): Promise<void> => {
  if (stopping) {
    process.exit(1);
  }

  stopping = true;
  stopMaintenance();
  setTimeout(() => {
    app.log.error("Shutdown took too long; exiting");
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS).unref();

  let failed = false;

  try {
    await app.close();
  } catch (error) {
    failed = true;
    app.log.error(error, "Closing the HTTP server failed");
  }

  try {
    await opened.close();
  } catch (error) {
    failed = true;
    app.log.error(error, "Closing the store failed");
  }

  process.exit(failed ? 1 : 0);
};

process.on("SIGINT", () => void shutdown());
process.on("SIGTERM", () => void shutdown());

await app.listen({
  host: process.env.HOST ?? "127.0.0.1",
  port: Number(process.env.PORT ?? "8080"),
});
