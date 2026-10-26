import { useEffect, useState } from "react";

import { call } from "../background.js";
import { useAsync } from "../useAsync.js";

/**
 * ### PendingSave
 *
 * Offers to save or update credentials the current page just submitted.
 *
 * @returns The prompt, or nothing when there is nothing to save
 */
export function PendingSave() {
  const [data, setData] = useState<
    | {
        pending?: {
          id: string;
          site: string;
          username?: string;
          updatesItemId?: string;
          updatesTitle?: string;
        };
        vaults: Array<{ id: string; name: string }>;
      }
    | undefined
  >(undefined);
  const [vaultId, setVaultId] = useState("");
  const { busy, error, run } = useAsync();

  useEffect(() => {
    run(async () => {
      const next = await call<NonNullable<typeof data>>({ type: "pending" });

      setData(next);
      setVaultId(next.vaults[0]?.id ?? "");
    });
  }, [run]);

  const pending = data?.pending;

  if (pending === undefined) {
    return null;
  }

  return (
    <div className="notice body" style={{ padding: 10 }}>
      <p>
        {pending.updatesItemId === undefined ? (
          <>
            Save the <strong>{pending.site}</strong> login
            {pending.username === undefined ? "" : ` (${pending.username})`} to
            keymember?
          </>
        ) : (
          <>
            The password for <strong>{pending.updatesTitle}</strong> changed.
            Update it in keymember?
          </>
        )}
      </p>
      {pending.updatesItemId === undefined ? (
        <select
          aria-label="Vault to save to"
          value={vaultId}
          onChange={(event) => {
            setVaultId(event.target.value);
          }}
        >
          {data?.vaults.map((vault) => (
            <option key={vault.id} value={vault.id}>
              {vault.name}
            </option>
          ))}
        </select>
      ) : null}
      <p className="error" role="alert">
        {error}
      </p>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary btn-small"
          disabled={
            busy || (pending.updatesItemId === undefined && vaultId === "")
          }
          onClick={() => {
            run(async () => {
              setData(
                await call({
                  type: "save-pending",
                  id: pending.id,
                  ...(pending.updatesItemId === undefined ? { vaultId } : {}),
                }),
              );
            });
          }}
        >
          {pending.updatesItemId === undefined ? "Save" : "Update"}
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-small"
          onClick={() => {
            run(async () => {
              setData(await call({ type: "dismiss-pending", id: pending.id }));
            });
          }}
        >
          Not now
        </button>
      </div>
    </div>
  );
}
