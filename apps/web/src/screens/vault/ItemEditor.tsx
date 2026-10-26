import type { ItemEditing, VaultReader, VaultView } from "@keymember/client";
import { generatePassword } from "@keymember/core";
import type { ItemDetails, ItemOverview } from "@keymember/core";
import { useState } from "react";

import { Dialog, ErrorText, Field, useAction } from "../../ui/primitives.js";

/**
 * ### ItemEditor
 *
 * Creates or edits a login item. Changing the password keeps the old one in history.
 *
 * @param props Session, target vaults, the item being edited and callbacks
 * @returns The dialog
 */
export function ItemEditor({
  session,
  vaults,
  defaultVaultId,
  itemId,
  onClose,
  onSaved,
}: {
  session: VaultReader & ItemEditing;
  vaults: ReadonlyArray<VaultView>;
  defaultVaultId: string | undefined;
  itemId?: string;
  onClose: () => void;
  onSaved: (itemId: string) => void;
}) {
  const existing = itemId === undefined ? undefined : session.getItem(itemId);
  const existingSummary =
    itemId === undefined
      ? undefined
      : session.listItems().find((item) => item.id === itemId);
  const [form, setForm] = useState({
    vaultId: existingSummary?.vaultId ?? defaultVaultId ?? vaults[0]?.id ?? "",
    title: existing?.overview.title ?? "",
    urls: existing?.overview.urls.join("\n") ?? "",
    username: existing?.details.username ?? "",
    password: existing?.details.password ?? "",
    totp: existing?.details.totp ?? "",
    notes: existing?.details.notes ?? "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const action = useAction();
  const set =
    (key: keyof typeof form) => (event: { target: { value: string } }) => {
      setForm({ ...form, [key]: event.target.value });
    };

  const save = (): Promise<void> =>
    action.run(async () => {
      const overview: ItemOverview = {
        type: existing?.overview.type ?? "login",
        title: form.title.trim(),
        urls: form.urls
          .split("\n")
          .map((url) => url.trim())
          .filter((url) => url.length > 0),
        tags: existing?.overview.tags ?? [],
      };
      const previousPassword = existing?.details.password;
      const history =
        previousPassword !== undefined && previousPassword !== form.password
          ? [
              {
                password: previousPassword,
                replacedAt: new Date().toISOString(),
              },
              ...(existing?.details.passwordHistory ?? []),
            ]
          : (existing?.details.passwordHistory ?? []);
      const details: ItemDetails = {
        ...(form.username.length > 0 ? { username: form.username } : {}),
        ...(form.password.length > 0 ? { password: form.password } : {}),
        ...(form.totp.trim().length > 0 ? { totp: form.totp.trim() } : {}),
        ...(form.notes.length > 0 ? { notes: form.notes } : {}),
        fields: existing?.details.fields ?? [],
        passwordHistory: history.slice(0, 20),
        // Passkeys are not editable here, but an edit must never drop them
        ...(existing?.details.passkeys === undefined
          ? {}
          : { passkeys: existing.details.passkeys }),
        // The web vault does not edit SSH keys; editing the item must not drop one
        ...(existing?.details.sshKey === undefined
          ? {}
          : { sshKey: existing.details.sshKey }),
      };

      if (itemId === undefined) {
        onSaved(await session.createItem(form.vaultId, overview, details));
      } else {
        await session.updateItem(itemId, overview, details, form.vaultId);
        onSaved(itemId);
      }
    });

  return (
    <Dialog
      title={itemId === undefined ? "New item" : "Edit item"}
      onClose={onClose}
    >
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void save();
        }}
      >
        <div className="field">
          <label htmlFor="item-vault">Vault</label>
          <select
            id="item-vault"
            className="input"
            value={form.vaultId}
            onChange={set("vaultId")}
          >
            {vaults.map((vault) => (
              <option key={vault.id} value={vault.id}>
                {vault.name}
              </option>
            ))}
          </select>
        </div>
        <Field
          label="Title"
          required
          autoFocus
          value={form.title}
          onChange={set("title")}
        />
        <div className="field">
          <label htmlFor="item-urls">Websites (one per line)</label>
          <textarea
            id="item-urls"
            className="input"
            rows={2}
            value={form.urls}
            onChange={set("urls")}
          />
        </div>
        <Field
          label="Username"
          value={form.username}
          onChange={set("username")}
          autoComplete="off"
        />
        <div className="field">
          <label htmlFor="item-password">Password</label>
          <div className="row">
            <input
              id="item-password"
              className="input mono"
              type={showPassword ? "text" : "password"}
              value={form.password}
              onChange={set("password")}
              autoComplete="new-password"
            />
            <button
              type="button"
              className="btn btn-small"
              onClick={() => {
                setShowPassword(!showPassword);
              }}
            >
              {showPassword ? "Hide" : "Show"}
            </button>
            <button
              type="button"
              className="btn btn-small"
              onClick={() => {
                setForm({ ...form, password: generatePassword() });
                setShowPassword(true);
              }}
            >
              Generate
            </button>
          </div>
        </div>
        <Field
          label="Two-factor authentication (TOTP)"
          value={form.totp}
          onChange={set("totp")}
          autoComplete="off"
          hint="otpauth:// URI or base32 seed"
        />
        <div className="field">
          <label htmlFor="item-notes">Notes</label>
          <textarea
            id="item-notes"
            className="input"
            value={form.notes}
            onChange={set("notes")}
          />
        </div>
        <ErrorText message={action.error} />
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={action.busy || form.vaultId === ""}
          >
            Save
          </button>
        </div>
      </form>
    </Dialog>
  );
}
