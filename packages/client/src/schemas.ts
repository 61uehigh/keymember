import { fromBase64Url, toBase64Url } from "@keymember/core";
import type { MemberCertificate } from "@keymember/core";
import { z } from "zod";

/**
 * ### b64
 *
 * Zod schema for a base64url string in a server response, decoded to bytes.
 */
export const b64 = z.string().transform((text, context) => {
  const decoded = fromBase64Url(text);

  if (decoded === undefined) {
    context.addIssue({ code: "custom", message: "Invalid base64url" });

    return z.NEVER;
  }

  return decoded;
});

/**
 * ### encode
 *
 * Encodes bytes for a request body.
 *
 * @param bytes Bytes to encode
 * @returns Unpadded base64url text
 */
export function encode(bytes: Uint8Array): string {
  return toBase64Url(bytes);
}

/**
 * ### roleSchema
 *
 * Membership role.
 */
export const roleSchema = z.enum(["owner", "admin", "member"]);

/**
 * ### kdfSchema
 *
 * KDF parameters as returned by prelogin. Bounds are enforced later by the core, not here.
 */
export const kdfSchema = z.object({
  algorithm: z.literal("argon2id"),
  memoryKiB: z.number(),
  iterations: z.number(),
  parallelism: z.number(),
});

/**
 * ### keysetSchema
 *
 * Stored account keyset as returned at login.
 */
export const keysetSchema = z.object({
  encryptedAccountKey: b64,
  encryptedPrivateKeys: b64,
  encryptionPublicKey: b64,
  signingPublicKey: b64,
  keysetVersion: z.number().int(),
  selfSignature: b64,
});

/**
 * ### tokensSchema
 *
 * Token pair returned at login and refresh.
 */
export const tokensSchema = z.object({
  accessToken: z.string(),
  refreshToken: z.string(),
  accessExpiresAt: z.string(),
});

/**
 * ### loginResponseSchema
 *
 * Response of `POST /api/auth/login`.
 */
export const loginResponseSchema = tokensSchema.extend({
  recoveryCancelled: z.boolean().optional(),
  user: z.object({
    id: z.string(),
    email: z.string(),
    name: z.string(),
    role: roleSchema,
    status: z.enum(["accepted", "confirmed", "suspended", "recovering"]),
  }),
  keyset: keysetSchema,
});

const certificateSchema = z.object({
  orgId: z.string(),
  userId: z.string(),
  email: z.string(),
  encryptionPublicKey: b64,
  signingPublicKey: b64,
  keysetVersion: z.number().int(),
  role: roleSchema,
  issuerId: z.string(),
  issuedAt: z.number().int(),
}) satisfies z.ZodType<MemberCertificate>;

/**
 * ### orgResponseSchema
 *
 * Response of `GET /api/org`: the organisation and its unverified member directory.
 */
export const orgResponseSchema = z.object({
  org: z.object({ id: z.string(), name: z.string() }),
  policies: z.object({
    requireTotp: z.boolean(),
    requireSso: z.boolean(),
    ssoAvailable: z.boolean(),
    ssoLinked: z.boolean(),
  }),
  recoveryKey: z
    .object({
      publicKey: b64,
      signature: b64,
      signerId: z.string(),
      wrappedPrivateKey: b64.nullable(),
    })
    .nullable(),
  members: z.array(
    z.object({
      userId: z.string(),
      email: z.string(),
      name: z.string(),
      role: roleSchema,
      status: z.enum(["accepted", "confirmed", "suspended", "recovering"]),
      publicBundle: z.object({
        userId: z.string(),
        encryptionPublicKey: b64,
        signingPublicKey: b64,
        keysetVersion: z.number().int(),
      }),
      selfSignature: b64,
      certificate: certificateSchema.nullable(),
      certificateSignature: b64.nullable(),
      invite: z
        .object({
          statement: z.object({
            orgId: z.string(),
            email: z.string(),
            role: z.enum(["admin", "member"]),
            issuerId: z.string(),
            issuedAt: z.number().int(),
            nonce: z.string().optional(),
          }),
          signature: b64,
          proof: b64.nullable().optional(),
        })
        .nullable(),
    }),
  ),
});

/**
 * ### groupCertificateSchema
 *
 * A group certificate as served, keys decoded.
 */
export const groupCertificateSchema = z.object({
  orgId: z.string(),
  groupId: z.string(),
  name: z.string(),
  encryptionPublicKey: b64,
  keysetVersion: z.number().int(),
  issuerId: z.string(),
  issuedAt: z.number().int(),
});

/**
 * ### syncResponseSchema
 *
 * Response of `GET /api/sync`.
 */
export const syncResponseSchema = z.object({
  revision: z.number().int(),
  // Set when the client's revision is ahead of the server's, as after a restore from backup
  reset: z.boolean().optional(),
  vaults: z.array(
    z.object({
      id: z.string(),
      kind: z.enum(["personal", "shared"]),
      encryptedName: b64,
      keyGeneration: z.number().int(),
      rotationDue: z.boolean(),
      access: z.array(
        z.object({
          principalType: z.enum(["user", "group"]),
          principalId: z.string(),
          wrappedKey: b64,
          keyGeneration: z.number().int(),
          permission: z.enum(["view", "edit", "manage"]),
          grantedBy: z.string().nullable(),
          grantSignature: b64.nullable(),
        }),
      ),
    }),
  ),
  groups: z.array(
    z.object({
      id: z.string(),
      encryptionPublicKey: b64,
      keysetVersion: z.number().int(),
      certificate: groupCertificateSchema,
      certificateSignature: b64,
      wrappedPrivateKey: b64,
      memberKeysetVersion: z.number().int(),
    }),
  ),
  items: z.array(
    z.object({
      id: z.string(),
      vaultId: z.string(),
      revision: z.number().int(),
      encryptedItemKey: b64,
      encryptedOverview: b64,
      encryptedDetails: b64,
    }),
  ),
  deletedItemIds: z.array(z.string()),
});

/**
 * ### groupsResponseSchema
 *
 * Response of `GET /api/org/groups`.
 */
export const groupsResponseSchema = z.object({
  groups: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      encryptionPublicKey: b64,
      keysetVersion: z.number().int(),
      certificate: groupCertificateSchema,
      certificateSignature: b64,
      members: z.array(
        z.object({ userId: z.string(), keysetVersion: z.number().int() }),
      ),
    }),
  ),
});

/**
 * ### preloginResponseSchema
 *
 * Response of `POST /api/auth/prelogin`: KDF inputs and a single-use login challenge.
 * `method` is `legacy` only for accounts that have not switched to signed login yet.
 */
export const preloginResponseSchema = z.object({
  salt: b64,
  kdf: kdfSchema,
  challengeId: z.string(),
  challenge: b64,
  method: z.enum(["signature", "legacy"]),
});

/**
 * ### parseResponse
 *
 * Validates a server response. A mismatch means the server is incompatible or hostile,
 * so it throws instead of returning a partial value.
 *
 * @param schema Expected shape
 * @param body Response body
 * @returns The validated body
 */
export function parseResponse<Output>(
  schema: z.ZodType<Output>,
  body: unknown,
): Output {
  const result = schema.safeParse(body);

  if (!result.success) {
    throw new Error("Server response has an unexpected shape", {
      cause: result.error,
    });
  }

  return result.data;
}

/**
 * ### sessionSnapshotSchema
 *
 * Shape of {@link Session.toSnapshot}, validated on restore because storage is outside
 * the process and may hold a stale or tampered value.
 */
export const sessionSnapshotSchema = z.object({
  v: z.literal(1),
  user: loginResponseSchema.shape.user,
  tokens: z.object({ accessToken: z.string(), refreshToken: z.string() }),
  secretKey: z.string(),
  keyset: z.object({
    accountKeyId: b64,
    accountKey: b64,
    encryptionPrivateKey: b64,
    signingPrivateKey: b64,
    keysetVersion: z.number().int(),
  }),
});

/**
 * ### SessionSnapshot
 *
 * Serialised session: the JSON-compatible input form of {@link sessionSnapshotSchema}.
 */
export type SessionSnapshot = z.input<typeof sessionSnapshotSchema>;
