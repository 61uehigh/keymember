import { useState } from "react";

import type { ItemRow } from "../../shared/messages.js";
import { call } from "../background.js";
import { copy } from "../copy.js";
import { useAsync } from "../useAsync.js";

/**
 * ### ItemList
 *
 * Item rows with fill and copy actions.
 *
 * @param props Rows and whether filling into the current tab makes sense
 * @returns The list
 */
export function ItemList({
  rows,
  canFill,
}: {
  rows: ReadonlyArray<ItemRow>;
  canFill: boolean;
}) {
  const [status, setStatus] = useState("");
  const { error, run } = useAsync();

  const copyField = (
    itemId: string,
    field: "username" | "password" | "totp",
    label: string,
  ): void => {
    run(async () => {
      const { value } = await call<{ value?: string }>({
        type: "reveal",
        itemId,
        field,
      });

      if (value === undefined) {
        throw new Error(`This item has no ${label}.`);
      }

      await copy(value);
      setStatus(`Copied the ${label}.`);
    });
  };

  if (rows.length === 0) {
    return <p className="muted small">No items.</p>;
  }

  return (
    <>
      <ul className="items">
        {rows.map((row) => (
          <li key={row.id} className="item">
            <div className="title">{row.title}</div>
            <div className="small muted">
              {row.insecure
                ? "Won't fill on an HTTP page"
                : (row.username ?? row.vaultName)}
            </div>
            <div className="row" style={{ marginTop: 6, flexWrap: "wrap" }}>
              {canFill ? (
                <button
                  type="button"
                  className="btn btn-primary btn-small"
                  disabled={row.insecure}
                  onClick={() => {
                    run(async () => {
                      const { filled } = await call<{ filled: number }>({
                        type: "fill",
                        itemId: row.id,
                      });

                      if (filled === 0) {
                        throw new Error("Couldn't find a field to fill.");
                      }

                      window.close();
                    });
                  }}
                >
                  Fill
                </button>
              ) : null}
              {row.username === undefined ? null : (
                <button
                  type="button"
                  className="btn btn-small"
                  onClick={() => {
                    copyField(row.id, "username", "username");
                  }}
                >
                  Copy username
                </button>
              )}
              <button
                type="button"
                className="btn btn-small"
                onClick={() => {
                  copyField(row.id, "password", "password");
                }}
              >
                Copy password
              </button>
              {row.hasTotp ? (
                <button
                  type="button"
                  className="btn btn-small"
                  onClick={() => {
                    copyField(row.id, "totp", "two-factor code");
                  }}
                >
                  Copy code
                </button>
              ) : null}
            </div>
          </li>
        ))}
      </ul>
      <p className="error" role="alert">
        {error}
      </p>
      <p className="small muted" role="status">
        {status}
      </p>
    </>
  );
}
