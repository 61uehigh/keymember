import { detectImportFormat, parseImport } from "@keymember/client";
import type { ImportFormat, ImportResult } from "@keymember/client";
import { useEffect, useMemo, useState } from "react";

import { useAppState, useSession } from "../lib/AppState.js";
import { ErrorText, useAction } from "../ui/primitives.js";

const FORMAT_LABELS: Readonly<Record<ImportFormat, string>> = {
  "chrome-csv": "Chrome / Edge passwords CSV",
  "bitwarden-json": "Bitwarden JSON (unencrypted export)",
  "1password-1pux": "1Password 1PUX",
  "cxf-json": "Credential Exchange Format (CXF JSON, includes passkeys)",
};

/**
 * ### isImportFormat
 *
 * Whether a select value names a known import format.
 *
 * @param value Option value
 * @returns Whether it is one of {@link FORMAT_LABELS}
 */
function isImportFormat(value: string): value is ImportFormat {
  return Object.hasOwn(FORMAT_LABELS, value);
}

/**
 * ### ImportScreen
 *
 * Imports another password manager's export. The file is read and parsed in the browser;
 * only encrypted items leave it.
 *
 * @returns The import screen
 */
export function ImportScreen() {
  const session = useSession();
  const { revision, touch } = useAppState();
  const [format, setFormat] = useState<ImportFormat>("chrome-csv");
  const [parsed, setParsed] = useState<ImportResult | undefined>(undefined);
  const [vaultId, setVaultId] = useState("");
  const [progress, setProgress] = useState<
    { done: number; total: number } | undefined
  >(undefined);
  const action = useAction();
  const { run } = action;

  useEffect(() => {
    void run(async () => {
      await session.sync();
      touch();
    });
  }, [run, session]); // eslint-disable-line react-hooks/exhaustive-deps

  const vaults = useMemo(
    () => session.listVaults().filter((vault) => vault.permission !== "view"),
    [session, revision], // eslint-disable-line react-hooks/exhaustive-deps
  );

  return (
    <div className="page-inner stack">
      <h1>Import</h1>
      <p className="muted">
        The file you exported from another password manager is read and
        encrypted inside this browser before it's uploaded. Delete the exported
        file after importing: it holds every password in plain text.
      </p>
      <div className="card stack">
        <div className="field">
          <label htmlFor="import-format">Format</label>
          <select
            id="import-format"
            className="input"
            value={format}
            onChange={(event) => {
              const { value } = event.target;

              if (isImportFormat(value)) {
                setFormat(value);
              }

              setParsed(undefined);
            }}
          >
            {Object.entries(FORMAT_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="import-file">File</label>
          <input
            id="import-file"
            className="input"
            type="file"
            accept=".csv,.json,.1pux"
            onChange={(event) => {
              const file = event.target.files?.[0];

              if (file === undefined) {
                return;
              }

              void action.run(async () => {
                const contents = new Uint8Array(await file.arrayBuffer());
                const detected =
                  detectImportFormat(file.name, contents) ?? format;

                setFormat(detected);
                setParsed(parseImport(detected, contents));
              });
            }}
          />
        </div>
        {parsed === undefined ? null : (
          <div className="stack">
            <p>
              Read <strong>{parsed.items.length}</strong> items
              {parsed.skipped.length > 0
                ? `; ${String(parsed.skipped.length)} will be skipped`
                : ""}
              .
            </p>
            {parsed.skipped.length > 0 ? (
              <details>
                <summary className="small muted">Skipped items</summary>
                <ul className="small">
                  {parsed.skipped.map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </details>
            ) : null}
            <div className="field">
              <label htmlFor="import-vault">Import into vault</label>
              <select
                id="import-vault"
                className="input"
                required
                value={vaultId}
                onChange={(event) => {
                  setVaultId(event.target.value);
                }}
              >
                <option value="">Choose…</option>
                {vaults.map((vault) => (
                  <option key={vault.id} value={vault.id}>
                    {vault.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="row">
              <button
                type="button"
                className="btn btn-primary"
                disabled={
                  action.busy || vaultId === "" || parsed.items.length === 0
                }
                onClick={() =>
                  void action.run(async () => {
                    setProgress({ done: 0, total: parsed.items.length });

                    for (const [index, item] of parsed.items.entries()) {
                      await session.createItem(
                        vaultId,
                        item.overview,
                        item.details,
                      );
                      setProgress({
                        done: index + 1,
                        total: parsed.items.length,
                      });
                    }

                    setParsed(undefined);
                    touch();
                  })
                }
              >
                Import
              </button>
              {progress === undefined ? null : (
                <span
                  className="small muted"
                  style={{ fontVariantNumeric: "tabular-nums" }}
                >
                  {progress.done} / {progress.total}
                </span>
              )}
            </div>
          </div>
        )}
        <ErrorText message={action.error} />
      </div>
    </div>
  );
}
