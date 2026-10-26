import { useSyncExternalStore } from "react";

/**
 * ### Route
 *
 * The current hash route: a path and its query parameters. Hash routing keeps every
 * route servable from one static `index.html` and keeps tokens out of server logs.
 */
export interface Route {
  /**
   * ### path
   *
   * Path after `#`, for example `/vault`.
   */
  readonly path: string;

  /**
   * ### params
   *
   * Query parameters after `?` in the hash.
   */
  readonly params: URLSearchParams;
}

/**
 * ### parseRoute
 *
 * Parses a hash route such as `#/join?invite=…`. Only the first `?` separates the path from the
 * query, so an unencoded `?` inside a parameter value stays part of that value.
 *
 * @param hash `location.hash`, with or without the leading `#`
 * @returns The route, `/` when the hash is empty
 */
export function parseRoute(hash: string): Route {
  const route = hash.replace(/^#/, "");
  const separator = route.indexOf("?");
  const path = separator === -1 ? route : route.slice(0, separator);
  const query = separator === -1 ? "" : route.slice(separator + 1);

  return { path: path === "" ? "/" : path, params: new URLSearchParams(query) };
}

/**
 * ### readRoute
 *
 * Parses `location.hash`.
 *
 * @returns The current route
 */
function readRoute(): Route {
  return parseRoute(location.hash);
}

let cached = readRoute();
let cachedHash = location.hash;

/**
 * ### snapshot
 *
 * Returns a stable route object until the hash changes, as `useSyncExternalStore` requires.
 *
 * @returns The current route
 */
function snapshot(): Route {
  if (location.hash !== cachedHash) {
    cachedHash = location.hash;
    cached = readRoute();
  }

  return cached;
}

/**
 * ### subscribe
 *
 * Subscribes to hash changes.
 *
 * @param onChange Callback for every change
 * @returns Unsubscribe function
 */
function subscribe(onChange: () => void): () => void {
  window.addEventListener("hashchange", onChange);

  return () => {
    window.removeEventListener("hashchange", onChange);
  };
}

/**
 * ### useRoute
 *
 * React hook returning the current hash route.
 *
 * @returns The current route
 */
export function useRoute(): Route {
  return useSyncExternalStore(subscribe, snapshot);
}

/**
 * ### navigate
 *
 * Moves to a hash route.
 *
 * @param path Path to open, optionally with a query string
 */
export function navigate(path: string): void {
  location.hash = path;
}

/**
 * ### clearSensitiveParams
 *
 * Removes one-time tokens from the address bar after they were read, so they do not
 * linger in history or get shared by a copied URL.
 *
 * @param path Path to keep
 */
export function clearSensitiveParams(path: string): void {
  history.replaceState(null, "", `${location.pathname}#${path}`);
}
