import { useEffect, useState } from "react";

import type { ItemRow } from "../../shared/ipc.js";
import { call } from "../ipc.js";
import { errorMessage, useAction } from "../useAction.js";

/**
 * ### Items
 *
 * Search and copy.
 *
 * @returns The tab
 */
export function Items() {
  const [query, setQuery] = useState("");
  const [rows, setRows] = useState<Array<ItemRow>>([]);
  const [status, setStatus] = useState("");
  const [searchError, setSearchError] = useState("");
  const action = useAction();
  const { run } = action;

  useEffect(() => {
    // Answers can arrive out of order while typing; only the latest query's answer counts
    let current = true;

    call<Array<ItemRow>>({ type: "search", query }).then(
      (next) => {
        if (current) {
          setRows(next);
          setSearchError("");
        }
      },
      (caught: unknown) => {
        if (current) {
          setSearchError(errorMessage(caught));
        }
      },
    );

    return () => {
      current = false;
    };
  }, [query]);

  const copy = (
    itemId: string,
    field: "username" | "password" | "totp",
    label: string,
  ): void => {
    run(async () => {
      await call({ type: "copy", itemId, field });
      setStatus(
        `Copied ${label}. The clipboard will be cleared in 30 seconds.`,
      );
    });
  };

  return (
    <div className="stack">
      <input
        type="search"
        aria-label="Search"
        placeholder="Title or URL"
        value={query}
        onChange={(event) => {
          setQuery(event.target.value);
        }}
      />
      <p className="muted small" role="status">
        {status}
      </p>
      <p className="error">{action.error || searchError}</p>
      <ul className="items">
        {rows.map((row) => (
          <li key={row.id} className="item">
            <div className="title">{row.title}</div>
            <div className="small muted">{row.username ?? row.vaultName}</div>
            <div className="row">
              {row.username === undefined ? null : (
                <button
                  type="button"
                  className="btn btn-small"
                  onClick={() => {
                    copy(row.id, "username", "username");
                  }}
                >
                  Copy username
                </button>
              )}
              {row.hasPassword ? (
                <button
                  type="button"
                  className="btn btn-small"
                  onClick={() => {
                    copy(row.id, "password", "password");
                  }}
                >
                  Copy password
                </button>
              ) : null}
              {row.hasTotp ? (
                <button
                  type="button"
                  className="btn btn-small"
                  onClick={() => {
                    copy(row.id, "totp", "two-factor code");
                  }}
                >
                  Copy code
                </button>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
