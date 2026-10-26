import type { ItemEditing, ItemSummary, VaultReader } from "@keymember/client";
import { useEffect, useRef } from "react";

import { ErrorText, useAction } from "../../ui/primitives.js";
import { SecretValue, TotpValue } from "../../ui/SecretFields.js";
import { typeLabel } from "./permissions.js";

/**
 * ### ItemDetail
 *
 * Decrypts and shows one item. Details are decrypted only while this panel is open.
 *
 * @param props Session, item and edit callbacks
 * @returns The detail panel
 */
export function ItemDetail({
  session,
  item,
  editable,
  onEdit,
  onShare,
  onDeleted,
}: {
  session: VaultReader & ItemEditing;
  item: ItemSummary;
  editable: boolean;
  onEdit: () => void;
  onShare: () => void;
  onDeleted: () => void;
}) {
  const { details } = session.getItem(item.id);
  const remove = useAction();
  const ref = useRef<HTMLElement>(null);

  useEffect(() => {
    // In the stacked mobile layout the detail sits below the list; bring it into view on selection
    if (window.matchMedia("(max-width: 860px)").matches) {
      ref.current?.scrollIntoView({ block: "start" });
    }
  }, []);

  return (
    <article ref={ref} className="detail stack">
      <div className="row spread wrap">
        <div>
          <h2>{item.overview.title}</h2>
          <p className="small muted">{typeLabel(item.overview.type)}</p>
        </div>
        <div className="row">
          <button type="button" className="btn btn-small" onClick={onShare}>
            Send as link
          </button>
          {editable ? (
            <button type="button" className="btn btn-small" onClick={onEdit}>
              Edit
            </button>
          ) : null}
          {editable ? (
            <button
              type="button"
              className="btn btn-danger btn-small"
              disabled={remove.busy}
              onClick={() => {
                if (window.confirm(`Delete "${item.overview.title}"?`)) {
                  void remove.run(async () => {
                    await session.deleteItem(item.id);
                    onDeleted();
                  });
                }
              }}
            >
              Delete
            </button>
          ) : null}
        </div>
      </div>
      <ErrorText message={remove.error} />
      <dl style={{ margin: 0 }}>
        {item.overview.urls.map((url) => (
          <div className="kv" key={url}>
            <dt>Website</dt>
            <dd>
              {/^https?:\/\//.test(url) ? (
                <a href={url} target="_blank" rel="noopener noreferrer">
                  {url}
                </a>
              ) : (
                url
              )}
            </dd>
            <span />
          </div>
        ))}
        {details.username === undefined ? null : (
          <SecretValue
            label="Username"
            value={details.username}
            secret={false}
          />
        )}
        {details.password === undefined ? null : (
          <SecretValue label="Password" value={details.password} secret />
        )}
        {details.totp === undefined ? null : <TotpValue value={details.totp} />}
        {details.fields.map((field, index) => (
          <SecretValue
            key={`${field.label}-${String(index)}`}
            label={field.label}
            value={field.value}
            secret={field.concealed}
          />
        ))}
      </dl>
      {details.sshKey === undefined ? null : (
        <div className="stack">
          <h3>SSH key</h3>
          <p className="small muted mono">{details.sshKey.fingerprint}</p>
          <SecretValue
            label="Public key"
            value={details.sshKey.publicKey}
            secret={false}
          />
          <p className="hint">
            Only the desktop app's SSH agent uses the private key. The web vault
            never shows it.
          </p>
        </div>
      )}
      {(details.passkeys ?? []).length === 0 ? null : (
        <div className="stack">
          <h3>Passkeys</h3>
          <ul className="small" style={{ margin: 0, paddingLeft: 18 }}>
            {(details.passkeys ?? []).map((passkey) => (
              <li key={passkey.credentialId}>
                {passkey.rpId} · {passkey.userName}{" "}
                <span className="muted">
                  ({new Date(passkey.createdAt).toLocaleDateString(undefined)})
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
      {details.notes === undefined ? null : (
        <div className="stack">
          <h3>Notes</h3>
          <p style={{ whiteSpace: "pre-wrap" }}>{details.notes}</p>
        </div>
      )}
      {details.passwordHistory.length === 0 ? null : (
        <details>
          <summary className="small muted">
            Previous passwords ({details.passwordHistory.length})
          </summary>
          <dl style={{ margin: 0 }}>
            {details.passwordHistory.map((entry) => (
              <SecretValue
                key={entry.replacedAt}
                label={new Date(entry.replacedAt).toLocaleDateString(undefined)}
                value={entry.password}
                secret
              />
            ))}
          </dl>
        </details>
      )}
    </article>
  );
}
