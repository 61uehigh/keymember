import { useCallback, useEffect, useState } from "react";
import type { SyntheticEvent } from "react";

import type { AgentInfo, SshKeyRow } from "../../shared/ipc.js";
import { Field } from "../Field.js";
import { call } from "../ipc.js";
import { useAction } from "../useAction.js";

/**
 * ### SshKeys
 *
 * SSH keys in the vault, adding keys, and how to use the agent.
 *
 * @returns The tab
 */
export function SshKeys() {
  const [keys, setKeys] = useState<Array<SshKeyRow>>([]);
  const [vaults, setVaults] = useState<Array<{ id: string; name: string }>>([]);
  const [info, setInfo] = useState<AgentInfo | undefined>(undefined);
  const [adding, setAdding] = useState(false);
  const [title, setTitle] = useState("");
  const [vaultId, setVaultId] = useState("");
  const [privateKey, setPrivateKey] = useState("");
  const [status, setStatus] = useState("");
  const action = useAction();
  const { run } = action;
  const refresh = useCallback(async () => {
    setKeys(await call<Array<SshKeyRow>>({ type: "ssh-keys" }));
  }, []);

  useEffect(() => {
    run(async () => {
      await refresh();
      setInfo(await call<AgentInfo>({ type: "agent-info" }));

      const writable = await call<Array<{ id: string; name: string }>>({
        type: "writable-vaults",
      });

      setVaults(writable);
      setVaultId(writable[0]?.id ?? "");
    });
  }, [refresh, run]);

  return (
    <div className="stack">
      <p className="error">{action.error}</p>
      <ul className="items">
        {keys.map((key) => (
          <li key={key.id} className="item">
            <div className="title">{key.title}</div>
            <div className="small muted mono">{key.fingerprint}</div>
            <div className="row">
              <button
                type="button"
                className="btn btn-small"
                onClick={() => {
                  run(async () => {
                    await call({
                      type: "copy",
                      itemId: key.id,
                      field: "publicKey",
                    });
                    setStatus("Copied the public key.");
                  });
                }}
              >
                Copy public key
              </button>
            </div>
          </li>
        ))}
      </ul>
      {keys.length === 0 ? (
        <p className="muted">No SSH keys in your vaults.</p>
      ) : null}
      <p className="muted small" role="status">
        {status}
      </p>
      {adding ? (
        <form
          className="stack card"
          onSubmit={(event: SyntheticEvent) => {
            event.preventDefault();
            run(async () => {
              await call({
                type: "add-ssh-key",
                vaultId,
                title,
                ...(privateKey.trim() === "" ? {} : { privateKey }),
              });
              setAdding(false);
              setTitle("");
              setPrivateKey("");
              await refresh();
            });
          }}
        >
          <Field
            label="Name"
            id="ssh-title"
            required
            placeholder="e.g. GitHub deploy key"
            value={title}
            onChange={(event) => {
              setTitle(event.target.value);
            }}
          />
          <label className="field">
            <span>vault</span>
            <select
              id="ssh-vault"
              value={vaultId}
              onChange={(event) => {
                setVaultId(event.target.value);
              }}
            >
              {vaults.map((vault) => (
                <option key={vault.id} value={vault.id}>
                  {vault.name}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>
              Private key to import (leave empty to generate a new Ed25519 key)
            </span>
            <textarea
              id="ssh-private-key"
              rows={4}
              spellCheck={false}
              value={privateKey}
              onChange={(event) => {
                setPrivateKey(event.target.value);
              }}
            />
          </label>
          <div className="row">
            <button
              type="submit"
              className="btn btn-primary"
              disabled={action.busy || vaultId === ""}
            >
              Save
            </button>
            <button
              type="button"
              className="btn"
              onClick={() => {
                setAdding(false);
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      ) : (
        <button
          type="button"
          className="btn"
          onClick={() => {
            setAdding(true);
          }}
        >
          Add SSH key
        </button>
      )}
      {info?.error === undefined ? null : (
        <div className="card stack small" role="alert">
          <strong>Couldn't start the SSH agent</strong>
          <p>{info.error}</p>
        </div>
      )}
      {info === undefined || info.error !== undefined ? null : (
        <div className="card stack small">
          <strong>Use with SSH</strong>
          <p>
            Add these lines to <code>~/.ssh/config</code> so ssh and git use
            keymember's keys. Each time a key is first used, this window asks
            whether to allow it.
          </p>
          <code className="block">
            Host *{"\n"} IdentityAgent &quot;{info.socketPath}&quot;
          </code>
        </div>
      )}
    </div>
  );
}
