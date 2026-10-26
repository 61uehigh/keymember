import { describe, expect, it } from "vitest";

import { migrate, PgliteDatabase } from "@keymember/server";

describe("migrations", () => {
  it("upgrades a database holding data written before the latest migrations", async () => {
    const db = new PgliteDatabase();

    try {
      await migrate(db, { through: 6 });

      // Data as a server at migration 6 wrote it: a self-certified owner, before confirmed_by existed
      await db.query(
        "INSERT INTO organizations (id, name) VALUES ('org', 'Acme')",
      );
      await db.query(
        `INSERT INTO users (id, email, name, account_id, salt, kdf, auth_verifier, enc_account_key,
                            enc_private_keys, encryption_public_key, signing_public_key,
                            keyset_version, self_signature)
         VALUES ('u1', 'a@example.com', 'A', 'ABCDEF', '\\x00', '{}', '\\x00', '\\x00', '\\x00',
                 '\\x00', '\\x00', 1, '\\x00')`,
      );
      await db.query(
        `INSERT INTO memberships (org_id, user_id, role, status, certificate)
         VALUES ('org', 'u1', 'member', 'confirmed', '{"issuerId": "u1"}')`,
      );

      await migrate(db);

      const [membership] = await db.query<{ confirmed_by: string | null }>(
        "SELECT confirmed_by FROM memberships WHERE user_id = 'u1'",
      );
      const [latest] = await db.query<{ id: number }>(
        "SELECT max(id) AS id FROM schema_migrations",
      );

      expect(membership?.confirmed_by).toBe("u1");
      expect(latest?.id).toBeGreaterThanOrEqual(9);
      // The latest migration added these
      await db.query("SELECT item_id FROM item_moves LIMIT 1");
    } finally {
      await db.close();
    }
  });

  it("applies each migration once when two servers start together", async () => {
    const db = new PgliteDatabase();

    try {
      await Promise.all([migrate(db), migrate(db)]);

      const rows = await db.query<{ id: number }>(
        "SELECT id FROM schema_migrations",
      );

      expect(new Set(rows.map((row) => row.id)).size).toBe(rows.length);
    } finally {
      await db.close();
    }
  });
});
