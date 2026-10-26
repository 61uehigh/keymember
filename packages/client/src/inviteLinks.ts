import { fromBase64Url, toBase64Url } from "@keymember/core";

/**
 * ### InviteLink
 *
 * What an invite link carries. Everything sits in the URL fragment, which browsers never send
 * to the server, so the server never sees the secret or gets to choose the roots.
 */
export interface InviteLink {
  /**
   * ### token
   *
   * One-time invite token the server issued.
   */
  readonly token: string;

  /**
   * ### email
   *
   * Invited email.
   */
  readonly email: string;

  /**
   * ### secret
   *
   * Secret the invitee proves their keys with; see `inviteLinkSecret` in the core.
   */
  readonly secret: Uint8Array;

  /**
   * ### roots
   *
   * Organisation keys the invitee should trust, by user id, as the inviting admin trusts them.
   */
  readonly roots: ReadonlyMap<string, Uint8Array>;
}

/**
 * ### inviteLinkUrl
 *
 * Builds the link an admin sends. It opens the web app's join page on the server.
 *
 * @param serverUrl Server origin, as members reach it
 * @param link Invite contents
 * @returns The link
 */
export function inviteLinkUrl(serverUrl: string, link: InviteLink): string {
  const params = new URLSearchParams({
    invite: link.token,
    email: link.email,
    secret: toBase64Url(link.secret),
    roots: [...link.roots]
      .map(([userId, key]) => `${userId}.${toBase64Url(key)}`)
      .join(","),
  });

  return `${new URL(serverUrl).origin}/#/join?${params.toString()}`;
}

/**
 * ### parseInviteParams
 *
 * Reads an invite from the join page's query parameters.
 *
 * @param params Parameters after `#/join?`
 * @returns The invite, or `undefined` when the parameters are not a complete link (for example a
 * token typed in by hand)
 */
export function parseInviteParams(
  params: URLSearchParams,
): InviteLink | undefined {
  const token = params.get("invite") ?? "";
  const email = params.get("email") ?? "";
  const secret = fromBase64Url(params.get("secret") ?? "");
  const roots = new Map<string, Uint8Array>();

  for (const entry of (params.get("roots") ?? "").split(",")) {
    const separator = entry.indexOf(".");
    const key = fromBase64Url(entry.slice(separator + 1));

    if (separator > 0 && key?.length === 32) {
      roots.set(entry.slice(0, separator), key);
    }
  }

  return token === "" ||
    email === "" ||
    secret?.length !== 32 ||
    roots.size === 0
    ? undefined
    : { token, email, secret, roots };
}

/**
 * ### parseInviteLink
 *
 * Reads an invite link pasted whole, for clients outside the browser.
 *
 * @param url Link as the admin sent it
 * @returns The server origin and invite, or `undefined` when it is not an invite link
 */
export function parseInviteLink(
  url: string,
): (InviteLink & { serverUrl: string }) | undefined {
  let parsed: URL;

  try {
    parsed = new URL(url.trim());
  } catch {
    // Not a URL at all; the caller reports that it is not an invite link
    return undefined;
  }

  const [path, query = ""] = parsed.hash.replace(/^#/, "").split("?");

  if (path !== "/join") {
    return undefined;
  }

  const link = parseInviteParams(new URLSearchParams(query));

  return link === undefined ? undefined : { ...link, serverUrl: parsed.origin };
}
