import { randomBytes, toBase64Url, utf8Encode } from "@keymember/core";
import { sha256 } from "@noble/hashes/sha2.js";

import type { SessionRepository } from "../repositories/SessionRepository.js";

/**
 * ### ACCESS_TOKEN_TTL_MS
 *
 * Lifetime of an access token: 15 minutes.
 */
export const ACCESS_TOKEN_TTL_MS = 15 * 60 * 1000;

/**
 * ### REFRESH_TOKEN_TTL_MS
 *
 * Lifetime of a refresh token: 30 days. Each use rotates it.
 */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * ### IssuedTokens
 *
 * A token pair returned to the client. Only hashes are stored server-side.
 */
export interface IssuedTokens {
  /**
   * ### accessToken
   *
   * Opaque bearer token for API calls.
   */
  readonly accessToken: string;

  /**
   * ### refreshToken
   *
   * Opaque one-time token for obtaining the next pair.
   */
  readonly refreshToken: string;

  /**
   * ### accessExpiresAt
   *
   * When the access token stops working, as an ISO 8601 timestamp.
   */
  readonly accessExpiresAt: string;
}

/**
 * ### hashToken
 *
 * Hashes a bearer token for storage and lookup. Tokens carry 256 bits of entropy, so a
 * plain hash is enough to make a leaked sessions table useless.
 *
 * @param token Token as presented by the client
 * @returns The stored hash
 */
export function hashToken(token: string): Uint8Array {
  return sha256(utf8Encode(token));
}

/**
 * ### issueTokens
 *
 * Creates a session row in the given family and returns its token pair.
 * A new login starts a new family; a refresh continues the family it came from.
 *
 * @param sessions Session storage
 * @param session Owner, device and family of the session
 * @param now Current time
 * @returns The new token pair
 */
export async function issueTokens(
  sessions: Pick<SessionRepository, "insert">,
  session: {
    userId: string;
    deviceId: string;
    deviceName: string;
    familyId: string;
  },
  now: Date,
): Promise<IssuedTokens> {
  const accessToken = toBase64Url(randomBytes(32));
  const refreshToken = toBase64Url(randomBytes(32));
  const accessExpiresAt = new Date(now.getTime() + ACCESS_TOKEN_TTL_MS);

  await sessions.insert({
    accessHash: hashToken(accessToken),
    refreshHash: hashToken(refreshToken),
    familyId: session.familyId,
    userId: session.userId,
    deviceId: session.deviceId,
    deviceName: session.deviceName,
    accessExpiresAt,
    refreshExpiresAt: new Date(now.getTime() + REFRESH_TOKEN_TTL_MS),
  });

  return {
    accessToken,
    refreshToken,
    accessExpiresAt: accessExpiresAt.toISOString(),
  };
}
