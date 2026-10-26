import { parse } from "tldts";

/**
 * ### SiteKey
 *
 * What two URLs must share to count as the same site: the registrable domain (eTLD+1,
 * private suffixes such as `github.io` included) for normal hosts, or the exact host for IP
 * addresses and single-label hosts like `localhost`; and in every case the same port, since
 * another port on the same host is another service.
 */
export interface SiteKey {
  /**
   * ### scheme
   *
   * `https:` or `http:`.
   */
  readonly scheme: "https:" | "http:";

  /**
   * ### site
   *
   * Registrable domain, or `host:port` when the host has none.
   */
  readonly site: string;

  /**
   * ### host
   *
   * Full host name, used to rank exact-host matches first.
   */
  readonly host: string;

  /**
   * ### port
   *
   * Explicit port, or `""` for the scheme's default.
   */
  readonly port: string;
}

/**
 * ### NON_HTTP_SCHEMES
 *
 * Schemes written without `//` (`javascript:alert(1)`), which must not be mistaken for a host
 * with a port (`intranet.example.com:8443`).
 */
const NON_HTTP_SCHEMES =
  /^(?:javascript|data|mailto|about|blob|vbscript|file|tel):/i;

/**
 * ### siteKeyOf
 *
 * Parses a URL into the parts used for matching. Item URLs saved without a scheme
 * (`github.com/login`, `intranet.example.com:8443`) are read as https. Anything that is not
 * http(s) yields `undefined`, so `javascript:`, `file:` and extension pages never match an item.
 *
 * @param url URL from an item or a page
 * @returns The site key, or `undefined` when the URL cannot be matched
 */
export function siteKeyOf(url: string): SiteKey | undefined {
  let parsed: URL;

  try {
    parsed = new URL(
      /^[a-z][a-z0-9+.-]*:\/\//i.test(url) || NON_HTTP_SCHEMES.test(url)
        ? url
        : `https://${url}`,
    );
  } catch {
    // Free-text item URLs are user data; an unparsable one simply never matches
    return undefined;
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return undefined;
  }

  const info = parse(parsed.hostname, { allowPrivateDomains: true });
  const site =
    info.isIp === true || info.domain === null ? parsed.hostname : info.domain;

  return {
    scheme: parsed.protocol,
    site: site.toLowerCase(),
    host: parsed.hostname.toLowerCase(),
    port: parsed.port,
  };
}

/**
 * ### MatchQuality
 *
 * How well an item URL matches a page: `host` (same host) ranks above `site` (same
 * registrable domain). `insecure` means the item was saved for https but the page is http,
 * which autofill must refuse.
 */
export type MatchQuality = "host" | "site" | "insecure";

/**
 * ### matchUrl
 *
 * Compares one item URL with the page URL.
 *
 * @param itemUrl URL stored on the item
 * @param pageUrl URL of the page or frame being filled
 * @returns The match quality, or `undefined` when the sites differ
 */
export function matchUrl(
  itemUrl: string,
  pageUrl: string,
): MatchQuality | undefined {
  const item = siteKeyOf(itemUrl);
  const page = siteKeyOf(pageUrl);

  if (
    item === undefined ||
    page?.site !== item.site ||
    page.port !== item.port
  ) {
    return undefined;
  }

  if (item.scheme === "https:" && page.scheme === "http:") {
    return "insecure";
  }

  return item.host === page.host ? "host" : "site";
}

/**
 * ### bestMatch
 *
 * The best match quality across all of an item's URLs.
 *
 * @param itemUrls URLs stored on the item
 * @param pageUrl URL of the page or frame being filled
 * @returns The best quality found, or `undefined` when no URL matches
 */
export function bestMatch(
  itemUrls: ReadonlyArray<string>,
  pageUrl: string,
): MatchQuality | undefined {
  const qualities = itemUrls.map((url) => matchUrl(url, pageUrl));

  if (qualities.includes("host")) {
    return "host";
  }

  if (qualities.includes("site")) {
    return "site";
  }

  return qualities.includes("insecure") ? "insecure" : undefined;
}
