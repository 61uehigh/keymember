/**
 * ### SCHEMA_MIGRATIONS
 *
 * Ordered schema migrations. Each entry runs once, inside a transaction, and is recorded in
 * `schema_migrations`; never edit an applied entry, append a new one instead.
 * Columns prefixed `enc_` or `wrapped_` hold client-side ciphertext the server cannot read.
 */
export const SCHEMA_MIGRATIONS: ReadonlyArray<{
  readonly id: number;
  readonly sql: string;
}> = [
  {
    id: 1,
    sql: `
      CREATE SEQUENCE change_seq;

      CREATE TABLE organizations (
        id          text PRIMARY KEY,
        name        text NOT NULL,
        created_at  timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE users (
        id                      text PRIMARY KEY,
        email                   text NOT NULL UNIQUE,
        name                    text NOT NULL,
        account_id              text NOT NULL UNIQUE,
        salt                    bytea NOT NULL,
        kdf                     jsonb NOT NULL,
        auth_verifier           bytea NOT NULL,
        enc_account_key         bytea NOT NULL,
        enc_private_keys        bytea NOT NULL,
        encryption_public_key   bytea NOT NULL,
        signing_public_key      bytea NOT NULL,
        keyset_version          integer NOT NULL,
        self_signature          bytea NOT NULL,
        totp_secret             bytea,
        totp_pending_secret     bytea,
        totp_last_step          bigint,
        created_at              timestamptz NOT NULL DEFAULT now()
      );

      CREATE TABLE memberships (
        org_id                  text NOT NULL REFERENCES organizations(id),
        user_id                 text NOT NULL REFERENCES users(id),
        role                    text NOT NULL CHECK (role IN ('owner', 'admin', 'member')),
        status                  text NOT NULL CHECK (status IN ('accepted', 'confirmed', 'suspended')),
        certificate             jsonb,
        certificate_signature   bytea,
        PRIMARY KEY (org_id, user_id)
      );

      CREATE TABLE invites (
        token_hash   bytea PRIMARY KEY,
        org_id       text NOT NULL REFERENCES organizations(id),
        email        text NOT NULL,
        role         text NOT NULL CHECK (role IN ('admin', 'member')),
        created_by   text NOT NULL REFERENCES users(id),
        expires_at   timestamptz NOT NULL,
        used_at      timestamptz
      );

      CREATE TABLE sessions (
        access_hash    bytea PRIMARY KEY,
        refresh_hash   bytea NOT NULL UNIQUE,
        family_id      text NOT NULL,
        user_id        text NOT NULL REFERENCES users(id),
        device_id      text NOT NULL,
        device_name    text NOT NULL,
        access_expires_at   timestamptz NOT NULL,
        refresh_expires_at  timestamptz NOT NULL,
        rotated_at     timestamptz,
        revoked_at     timestamptz,
        created_at     timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX sessions_family ON sessions(family_id);

      CREATE TABLE vaults (
        id              text PRIMARY KEY,
        org_id          text NOT NULL REFERENCES organizations(id),
        kind            text NOT NULL CHECK (kind IN ('personal', 'shared')),
        enc_name        bytea NOT NULL,
        key_generation  integer NOT NULL,
        created_by      text NOT NULL REFERENCES users(id),
        revision        bigint NOT NULL DEFAULT nextval('change_seq'),
        deleted_at      timestamptz
      );

      CREATE TABLE vault_access (
        vault_id        text NOT NULL REFERENCES vaults(id),
        principal_id    text NOT NULL REFERENCES users(id),
        wrapped_key     bytea NOT NULL,
        key_generation  integer NOT NULL,
        permission      text NOT NULL CHECK (permission IN ('view', 'edit', 'manage')),
        revision        bigint NOT NULL DEFAULT nextval('change_seq'),
        PRIMARY KEY (vault_id, principal_id)
      );

      CREATE TABLE items (
        id                  text PRIMARY KEY,
        vault_id            text NOT NULL REFERENCES vaults(id),
        enc_item_key        bytea NOT NULL,
        enc_overview        bytea NOT NULL,
        enc_details         bytea NOT NULL,
        revision            bigint NOT NULL DEFAULT nextval('change_seq'),
        created_by          text NOT NULL REFERENCES users(id),
        updated_by          text NOT NULL REFERENCES users(id),
        updated_at          timestamptz NOT NULL DEFAULT now(),
        deleted_at          timestamptz
      );
      CREATE INDEX items_vault_revision ON items(vault_id, revision);

      CREATE TABLE audit_events (
        id          bigserial PRIMARY KEY,
        org_id      text NOT NULL REFERENCES organizations(id),
        actor_id    text,
        action      text NOT NULL,
        target_id   text,
        detail      jsonb NOT NULL DEFAULT '{}'::jsonb,
        ip          text,
        at          timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX audit_events_org_at ON audit_events(org_id, at DESC);
    `,
  },
  {
    id: 2,
    sql: `
      ALTER TABLE organizations
        ADD COLUMN recovery_public_key bytea,
        ADD COLUMN recovery_key_signature bytea,
        ADD COLUMN recovery_key_signer text REFERENCES users(id),
        ADD COLUMN require_totp boolean NOT NULL DEFAULT false;

      ALTER TABLE memberships DROP CONSTRAINT memberships_status_check;
      ALTER TABLE memberships ADD CONSTRAINT memberships_status_check
        CHECK (status IN ('accepted', 'confirmed', 'suspended', 'recovering'));

      CREATE TABLE recovery_key_access (
        org_id               text NOT NULL REFERENCES organizations(id),
        admin_id             text NOT NULL REFERENCES users(id),
        wrapped_private_key  bytea NOT NULL,
        PRIMARY KEY (org_id, admin_id)
      );

      CREATE TABLE vault_recovery (
        vault_id        text PRIMARY KEY REFERENCES vaults(id),
        wrapped_key     bytea NOT NULL,
        key_generation  integer NOT NULL
      );

      CREATE TABLE recoveries (
        id               text PRIMARY KEY,
        org_id           text NOT NULL REFERENCES organizations(id),
        user_id          text NOT NULL REFERENCES users(id),
        requested_by     text NOT NULL REFERENCES users(id),
        approved_by      text REFERENCES users(id),
        status           text NOT NULL CHECK (status IN ('pending', 'approved', 'rekeyed', 'completed', 'cancelled')),
        token_hash       bytea UNIQUE,
        token_expires_at timestamptz,
        vault_snapshot   jsonb NOT NULL,
        created_at       timestamptz NOT NULL DEFAULT now(),
        updated_at       timestamptz NOT NULL DEFAULT now()
      );
      CREATE UNIQUE INDEX recoveries_one_open_per_user ON recoveries(user_id)
        WHERE status IN ('pending', 'approved', 'rekeyed');
    `,
  },
  {
    id: 3,
    sql: `
      ALTER TABLE vault_access DROP CONSTRAINT vault_access_principal_id_fkey;
      ALTER TABLE vault_access
        ADD COLUMN principal_type text NOT NULL DEFAULT 'user' CHECK (principal_type IN ('user', 'group'));

      CREATE TABLE groups (
        id                     text PRIMARY KEY,
        org_id                 text NOT NULL REFERENCES organizations(id),
        name                   text NOT NULL,
        encryption_public_key  bytea NOT NULL,
        keyset_version         integer NOT NULL,
        certificate            jsonb NOT NULL,
        certificate_signature  bytea NOT NULL,
        recovery_wrapped_key   bytea,
        created_by             text NOT NULL REFERENCES users(id),
        created_at             timestamptz NOT NULL DEFAULT now(),
        deleted_at             timestamptz,
        revision               bigint NOT NULL DEFAULT nextval('change_seq')
      );

      CREATE TABLE group_members (
        group_id             text NOT NULL REFERENCES groups(id),
        user_id              text NOT NULL REFERENCES users(id),
        wrapped_private_key  bytea NOT NULL,
        keyset_version       integer NOT NULL,
        revision             bigint NOT NULL DEFAULT nextval('change_seq'),
        PRIMARY KEY (group_id, user_id)
      );
      CREATE INDEX group_members_user ON group_members(user_id);

      ALTER TABLE recoveries ADD COLUMN group_snapshot jsonb NOT NULL DEFAULT '[]';
    `,
  },
  {
    id: 4,
    sql: `
      ALTER TABLE organizations ADD COLUMN require_sso boolean NOT NULL DEFAULT false;
      ALTER TABLE users ADD COLUMN sso_subject text UNIQUE;

      -- Pending SSO checks: a login waiting for the identity provider, or a session being linked
      CREATE TABLE sso_tickets (
        id              text PRIMARY KEY,
        secret_hash     bytea NOT NULL,
        kind            text NOT NULL CHECK (kind IN ('login', 'link')),
        user_id         text NOT NULL REFERENCES users(id),
        family_id       text,
        device_id       text,
        device_name     text,
        state           text NOT NULL UNIQUE,
        nonce           text NOT NULL,
        code_verifier   text NOT NULL,
        status          text NOT NULL CHECK (status IN ('pending', 'verified', 'failed', 'used')),
        failure         text,
        subject         text,
        enc_refresh_token bytea,
        expires_at      timestamptz NOT NULL,
        created_at      timestamptz NOT NULL DEFAULT now()
      );

      -- One row per login (session family) that passed SSO. The provider refresh token is
      -- server-encrypted and used to re-check the account on every keymember refresh
      CREATE TABLE sso_sessions (
        family_id         text PRIMARY KEY,
        user_id           text NOT NULL REFERENCES users(id),
        subject           text NOT NULL,
        enc_refresh_token bytea NOT NULL,
        checked_at        timestamptz NOT NULL
      );

      ALTER TABLE vaults ADD COLUMN rotation_due_at timestamptz;
    `,
  },
  {
    id: 5,
    sql: `
      -- Share links: an encrypted snapshot of one item for someone outside the vault. The key
      -- lives only in the link fragment. ciphertext is cleared once the link can no longer open
      CREATE TABLE shares (
        id               text PRIMARY KEY,
        org_id           text NOT NULL REFERENCES organizations(id),
        vault_id         text NOT NULL REFERENCES vaults(id),
        item_id          text NOT NULL REFERENCES items(id),
        created_by       text NOT NULL REFERENCES users(id),
        ciphertext       bytea,
        access_hash      bytea NOT NULL,
        passphrase       boolean NOT NULL,
        expires_at       timestamptz NOT NULL,
        max_views        integer NOT NULL CHECK (max_views BETWEEN 1 AND 100),
        views            integer NOT NULL DEFAULT 0,
        failed_attempts  integer NOT NULL DEFAULT 0,
        revoked_at       timestamptz,
        last_opened_at   timestamptz,
        created_at       timestamptz NOT NULL DEFAULT now()
      );
      CREATE INDEX shares_item ON shares(item_id);
      CREATE INDEX shares_creator ON shares(created_by);
    `,
  },
  {
    id: 6,
    sql: `
      -- Signed-challenge login: the server keeps the login public key instead of a verifier.
      -- Accounts without one still log in with the legacy verifier once and are switched over
      ALTER TABLE users ADD COLUMN auth_public_key bytea;
      ALTER TABLE users ALTER COLUMN auth_verifier DROP NOT NULL;

      CREATE TABLE login_challenges (
        id          text PRIMARY KEY,
        email       text NOT NULL,
        challenge   bytea NOT NULL,
        expires_at  timestamptz NOT NULL,
        used_at     timestamptz
      );
    `,
  },
  {
    id: 7,
    sql: `
      -- Who granted each wrapped vault key, with their signature over it
      ALTER TABLE vault_access ADD COLUMN granted_by text REFERENCES users(id);
      ALTER TABLE vault_access ADD COLUMN grant_signature bytea;

      -- The inviting admin's signed statement of email and role
      ALTER TABLE invites ADD COLUMN statement jsonb;
      ALTER TABLE invites ADD COLUMN signature bytea;

      -- Who confirmed each member and when, for the two-admin recovery rule
      ALTER TABLE memberships ADD COLUMN confirmed_by text REFERENCES users(id);
      ALTER TABLE memberships ADD COLUMN confirmed_at timestamptz;
      UPDATE memberships SET confirmed_by = certificate->>'issuerId' WHERE certificate IS NOT NULL;

      -- The requesting admin's signature over whom a recovery is for
      ALTER TABLE recoveries ADD COLUMN request_signature bytea;
    `,
  },
  {
    id: 8,
    sql: `
      -- The invitee's proof, made with the secret in the invite link, that the keys they
      -- published are theirs. The inviting admin checks it instead of comparing fingerprints
      ALTER TABLE invites ADD COLUMN proof bytea;

      -- The organisation keys a user trusts, signed by the user, so their other devices can
      -- adopt them without a fingerprint check
      ALTER TABLE users ADD COLUMN trusted_roots jsonb;
      ALTER TABLE users ADD COLUMN trusted_roots_signature bytea;
    `,
  },
  {
    id: 9,
    sql: `
      -- Where items moved from, so members who could see the old vault but not the new one
      -- are told to drop their copy. One row per move, with the move's own revision
      CREATE TABLE item_moves (
        item_id        text NOT NULL REFERENCES items(id),
        from_vault_id  text NOT NULL REFERENCES vaults(id),
        revision       bigint NOT NULL DEFAULT nextval('change_seq'),
        PRIMARY KEY (item_id, revision)
      );
      CREATE INDEX item_moves_from_vault ON item_moves(from_vault_id, revision);

      -- latestRevision reads the highest revision of each table on every sync
      CREATE INDEX items_revision ON items(revision);
      CREATE INDEX vault_access_revision ON vault_access(revision);
      CREATE INDEX group_members_revision ON group_members(revision);
      CREATE INDEX groups_revision ON groups(revision);
      CREATE INDEX vaults_revision ON vaults(revision);

      -- A member's grants are looked up by principal alone (sync, suspension)
      CREATE INDEX vault_access_principal ON vault_access(principal_id);

      -- Expired records are removed in pages by time
      CREATE INDEX login_challenges_expires ON login_challenges(expires_at);
      CREATE INDEX sso_tickets_expires ON sso_tickets(expires_at);
      CREATE INDEX sessions_refresh_expires ON sessions(refresh_expires_at);
    `,
  },
  {
    id: 10,
    sql: `
      -- Who handed each member their copy of a group key, with their signature over it. Group
      -- rotation re-wraps the new key only to members whose membership an admin signed
      ALTER TABLE group_members ADD COLUMN granted_by text REFERENCES users(id);
      ALTER TABLE group_members ADD COLUMN membership_signature bytea;

      -- Finds a user's earlier logins from a device (login rate limiting) and all their logins
      CREATE INDEX sessions_user_device ON sessions(user_id, device_id);
    `,
  },
];
