import { useState } from "react";

import type { DesktopState } from "../../shared/ipc.js";
import { Items } from "./Items.js";
import { Settings } from "./Settings.js";
import { SshKeys } from "./SshKeys.js";

/**
 * ### Main
 *
 * Items, SSH keys and settings, with a reminder while the organisation's owner is not yet
 * confirmed on this computer: until then, vaults shared by others stay hidden.
 *
 * @param props State, change handler, and how to return to owner confirmation
 * @returns The main view
 */
export function Main({
  state,
  onChange,
  onPinOwner,
}: {
  state: DesktopState;
  onChange: (state: DesktopState) => void;
  onPinOwner: () => void;
}) {
  const [tab, setTab] = useState<"items" | "ssh" | "settings">("items");

  return (
    <div className="stack">
      {state.pinned ? null : (
        <div className="notice" role="status">
          <p className="small">
            Vaults shared by others are hidden until you verify the organization
            owner.
          </p>
          <button type="button" className="btn btn-small" onClick={onPinOwner}>
            Verify organization
          </button>
        </div>
      )}
      <nav className="tabs" role="tablist">
        {(
          [
            ["items", "Items"],
            ["ssh", "SSH keys"],
            ["settings", "Settings"],
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
      </nav>
      {tab === "items" ? <Items /> : null}
      {tab === "ssh" ? <SshKeys /> : null}
      {tab === "settings" ? (
        <Settings state={state} onChange={onChange} />
      ) : null}
    </div>
  );
}
