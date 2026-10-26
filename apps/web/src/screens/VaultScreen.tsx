import { matchesQuery } from "@keymember/client";
import type { ItemSummary, VaultView } from "@keymember/client";
import { useEffect, useMemo, useState } from "react";

import { useAppState, useSession } from "../lib/AppState.js";
import { ErrorText, useAction } from "../ui/primitives.js";
import { ShareLinkDialog } from "./ShareScreens.js";
import { PERMISSION_LABELS, canEdit, typeLabel } from "./vault/permissions.js";
import { ItemDetail } from "./vault/ItemDetail.js";
import { NewVaultDialog } from "./vault/NewVaultDialog.js";
import { ItemEditor } from "./vault/ItemEditor.js";
import { ShareDialog } from "./vault/ShareDialog.js";

/**
 * ### VaultScreen
 *
 * Three-pane vault browser: vaults, items with search, and the selected item.
 *
 * @returns The vault screen
 */
export function VaultScreen() {
  const session = useSession();
  const { revision, touch } = useAppState();
  const [vaultId, setVaultId] = useState<string | undefined>(undefined);
  const [itemId, setItemId] = useState<string | undefined>(undefined);
  const [query, setQuery] = useState("");
  const [dialog, setDialog] = useState<
    | { kind: "new-vault" }
    | { kind: "item"; itemId?: string }
    | { kind: "share"; vault: VaultView }
    | { kind: "share-link"; item: ItemSummary }
    | undefined
  >(undefined);
  const sync = useAction();
  const { run } = sync;

  useEffect(() => {
    void run(async () => {
      await session.sync();
      touch();
    });
    // touch only bumps a counter; re-syncing on its identity change would loop
  }, [session, run]); // eslint-disable-line react-hooks/exhaustive-deps

  const vaults = useMemo(() => session.listVaults(), [session, revision]); // eslint-disable-line react-hooks/exhaustive-deps
  const selectedVault = vaults.find((vault) => vault.id === vaultId);
  const items = useMemo(
    () =>
      session
        .listItems(vaultId)
        .filter((item) => matchesQuery(item, query))
        .sort((a, b) =>
          a.overview.title.localeCompare(b.overview.title, undefined),
        ),
    // revision changes when the session's cache does; the session object itself stays the same
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [session, vaultId, query, revision],
  );
  const selectedItem = items.find((item) => item.id === itemId);
  const editableVaults = vaults.filter((vault) => canEdit(vault.permission));

  return (
    <div className="vault-layout">
      <section className="pane" aria-label="Vaults">
        <div className="pane-header spread">
          <h2>Vault</h2>
          <button
            type="button"
            className="btn btn-small"
            onClick={() => {
              setDialog({ kind: "new-vault" });
            }}
          >
            + New vault
          </button>
        </div>
        <ul className="list">
          <li>
            <button
              type="button"
              aria-current={vaultId === undefined}
              onClick={() => {
                setVaultId(undefined);
                setItemId(undefined);
              }}
            >
              <span className="title">All items</span>
            </button>
          </li>
          {vaults.map((vault) => (
            <li key={vault.id}>
              <button
                type="button"
                aria-current={vault.id === vaultId}
                onClick={() => {
                  setVaultId(vault.id);
                  setItemId(undefined);
                }}
              >
                <span className="title">{vault.name}</span>
                <span className="small muted">
                  {vault.kind === "personal" ? "Personal" : "Shared"} ·{" "}
                  {PERMISSION_LABELS[vault.permission]}
                </span>
                {vault.rotationDue && vault.permission === "manage" ? (
                  <span className="badge badge-warn">Key rotation needed</span>
                ) : null}
              </button>
            </li>
          ))}
        </ul>
        <ErrorText message={sync.error} />
      </section>

      <section className="pane" aria-label="Items">
        <div className="pane-header">
          <input
            className="input"
            type="search"
            placeholder="Search by title or URL"
            aria-label="Search items"
            value={query}
            onChange={(event) => {
              setQuery(event.target.value);
            }}
          />
          <button
            type="button"
            className="btn btn-primary btn-small"
            disabled={editableVaults.length === 0}
            onClick={() => {
              setDialog({ kind: "item" });
            }}
          >
            + Item
          </button>
        </div>
        {selectedVault?.permission === "manage" && selectedVault.rotationDue ? (
          <div className="notice" style={{ margin: "8px 12px" }}>
            Someone who could open this vault has left the organization. Rotate
            the key in &ldquo;Manage sharing&rdquo;.
          </div>
        ) : null}
        {selectedVault?.permission === "manage" &&
        selectedVault.kind === "shared" ? (
          <div className="row" style={{ padding: "8px 12px" }}>
            <button
              type="button"
              className="btn btn-small"
              onClick={() => {
                setDialog({ kind: "share", vault: selectedVault });
              }}
            >
              Manage sharing
            </button>
          </div>
        ) : null}
        {items.length === 0 ? (
          <p className="empty">{sync.busy ? "Syncing…" : "No items."}</p>
        ) : (
          <ul className="list">
            {items.map((item) => (
              <li key={item.id}>
                <button
                  type="button"
                  aria-current={item.id === itemId}
                  onClick={() => {
                    setItemId(item.id);
                  }}
                >
                  <span className="title">{item.overview.title}</span>
                  <span className="small muted">
                    {item.overview.urls[0] ?? typeLabel(item.overview.type)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="pane" aria-label="Item details">
        {selectedItem === undefined ? (
          <p className="empty">Select an item.</p>
        ) : (
          <ItemDetail
            key={selectedItem.id}
            session={session}
            item={selectedItem}
            onShare={() => {
              setDialog({ kind: "share-link", item: selectedItem });
            }}
            editable={canEdit(
              vaults.find((vault) => vault.id === selectedItem.vaultId)
                ?.permission ?? "view",
            )}
            onEdit={() => {
              setDialog({ kind: "item", itemId: selectedItem.id });
            }}
            onDeleted={() => {
              setItemId(undefined);
              touch();
            }}
          />
        )}
      </section>

      {dialog?.kind === "new-vault" ? (
        <NewVaultDialog
          session={session}
          onClose={() => {
            setDialog(undefined);
          }}
          onCreated={(id) => {
            setDialog(undefined);
            setVaultId(id);
            touch();
          }}
        />
      ) : null}
      {dialog?.kind === "item" ? (
        <ItemEditor
          session={session}
          vaults={editableVaults}
          defaultVaultId={
            selectedVault !== undefined && canEdit(selectedVault.permission)
              ? selectedVault.id
              : undefined
          }
          {...(dialog.itemId === undefined ? {} : { itemId: dialog.itemId })}
          onClose={() => {
            setDialog(undefined);
          }}
          onSaved={(id) => {
            setDialog(undefined);
            setItemId(id);
            touch();
          }}
        />
      ) : null}
      {dialog?.kind === "share-link" ? (
        <ShareLinkDialog
          session={session}
          item={dialog.item}
          onClose={() => {
            setDialog(undefined);
          }}
        />
      ) : null}
      {dialog?.kind === "share" ? (
        <ShareDialog
          session={session}
          vault={dialog.vault}
          onClose={() => {
            setDialog(undefined);
            touch();
          }}
        />
      ) : null}
    </div>
  );
}
