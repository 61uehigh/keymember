import { useState } from "react";

import type { ExtensionState } from "../../shared/messages.js";
import { call } from "../background.js";
import { Generator } from "./Generator.js";
import { SearchItems, SiteItems } from "./ItemTabs.js";
import { PendingSave } from "./PendingSave.js";
import { Shell } from "./Shell.js";
import { useAsync } from "../useAsync.js";

/**
 * ### Main
 *
 * Unlocked view: pending save, items for this site, search and generator.
 *
 * @param props State, lock handler, and how to open the organisation check
 * @returns The main screen
 */
export function Main({
  state,
  onLocked,
  onPin,
}: {
  state: ExtensionState;
  onLocked: (state: ExtensionState) => void;
  onPin: () => void;
}) {
  const [tab, setTab] = useState<"site" | "search" | "generate">("site");
  const { run } = useAsync();

  return (
    <Shell
      action={
        <button
          type="button"
          className="btn btn-small"
          onClick={() => {
            run(async () => {
              onLocked(await call<ExtensionState>({ type: "lock" }));
            });
          }}
        >
          Lock
        </button>
      }
    >
      {state.pinned ? null : (
        <div className="notice">
          <p className="small">
            Verify your organization. Until you do, vaults that others share
            with you stay hidden.
          </p>
          <button type="button" className="btn btn-small" onClick={onPin}>
            Verify organization
          </button>
        </div>
      )}
      <PendingSave />
      <div className="tabs" role="tablist">
        {(
          [
            ["site", "This site"],
            ["search", "Search"],
            ["generate", "Generator"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={tab === id}
            onClick={() => {
              setTab(id);
            }}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === "site" ? <SiteItems /> : null}
      {tab === "search" ? <SearchItems /> : null}
      {tab === "generate" ? <Generator /> : null}
      <p className="small muted">{state.user?.email}</p>
    </Shell>
  );
}
