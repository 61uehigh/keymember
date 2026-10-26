import type { VaultAccessControl } from "@keymember/client";
import { useState } from "react";

import { Dialog, ErrorText, Field, useAction } from "../../ui/primitives.js";

/**
 * ### NewVaultDialog
 *
 * Creates a personal or shared vault; sharing happens afterwards in the share dialog.
 *
 * @param props Session and dialog callbacks
 * @returns The dialog
 */
export function NewVaultDialog({
  session,
  onClose,
  onCreated,
}: {
  session: VaultAccessControl;
  onClose: () => void;
  onCreated: (vaultId: string) => void;
}) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState<"personal" | "shared">("shared");
  const action = useAction();

  return (
    <Dialog title="New vault" onClose={onClose}>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            onCreated(await session.createVault(name.trim(), kind, []));
          });
        }}
      >
        <Field
          label="Name"
          required
          autoFocus
          value={name}
          onChange={(event) => {
            setName(event.target.value);
          }}
        />
        <div className="field">
          <label htmlFor="vault-kind">Type</label>
          <select
            id="vault-kind"
            className="input"
            value={kind}
            onChange={(event) => {
              setKind(
                event.target.value === "personal" ? "personal" : "shared",
              );
            }}
          >
            <option value="shared">
              Shared (can be shared with teammates)
            </option>
            <option value="personal">Personal (only you)</option>
          </select>
        </div>
        <ErrorText message={action.error} />
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={action.busy}
          >
            Create
          </button>
        </div>
      </form>
    </Dialog>
  );
}
