import { useEffect, useState } from "react";

import type { ItemRow } from "../../shared/messages.js";
import { call } from "../background.js";
import { ItemList } from "./ItemList.js";
import { useAsync } from "../useAsync.js";

/**
 * ### SiteItems
 *
 * Items matching the active tab.
 *
 * @returns The list for this site
 */
export function SiteItems() {
  const [rows, setRows] = useState<Array<ItemRow> | undefined>(undefined);
  const { error, run } = useAsync();

  useEffect(() => {
    run(async () => {
      setRows(await call<Array<ItemRow>>({ type: "matches" }));
    });
  }, [run]);

  return (
    <>
      {rows === undefined ? (
        <p className="muted small">Loading…</p>
      ) : (
        <ItemList rows={rows} canFill />
      )}
      <p className="error">{error}</p>
    </>
  );
}

/**
 * ### SearchItems
 *
 * Search across all items.
 *
 * @returns The search view
 */
export function SearchItems() {
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<Array<ItemRow>>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    // Answers can arrive out of order while typing; only the latest query's answer is shown
    let latest = true;

    call<Array<ItemRow>>({ type: "search", query }).then(
      (found) => {
        if (latest) {
          setRows(found);
          setError("");
        }
      },
      (caught: unknown) => {
        if (latest) {
          setError(caught instanceof Error ? caught.message : String(caught));
        }
      },
    );

    return () => {
      latest = false;
    };
  }, [query]);

  return (
    <>
      <input
        type="search"
        aria-label="Search"
        placeholder="Title or URL"
        autoFocus
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
        }}
      />
      <p className="error" role="alert">
        {error}
      </p>
      <ItemList rows={rows} canFill />
    </>
  );
}
