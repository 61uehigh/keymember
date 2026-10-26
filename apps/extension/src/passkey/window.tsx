import { StrictMode, useCallback, useEffect, useState } from "react";
import type { SyntheticEvent } from "react";
import { createRoot } from "react-dom/client";

import type {
  ExtensionState,
  PasskeyDecision,
  PasskeyRequestView,
  PopupRequest,
} from "../shared/messages.js";
import { isRecord } from "../shared/records.js";

const requestId = location.hash.slice(1);

/**
 * ### call
 *
 * Sends a request to the background.
 *
 * @param request Request to send
 * @returns The response
 */
async function call<T>(
  request:
    | PopupRequest
    | {
        type: "passkey-request" | "passkey-decide";
        id: string;
        decision?: PasskeyDecision;
      },
): Promise<T> {
  const response: unknown = await chrome.runtime.sendMessage(request);

  if (isRecord(response) && typeof response.error === "string") {
    throw new Error(response.error);
  }

  // Each request type has a fixed response shape
  return response as T;
}

/**
 * ### decide
 *
 * Sends the user's choice; the background closes this window afterwards.
 *
 * @param decision The choice
 */
async function decide(decision: PasskeyDecision): Promise<void> {
  await call({ type: "passkey-decide", id: requestId, decision });
}

/**
 * ### PasskeyWindow
 *
 * Consent window for a site's passkey request: unlock if needed, then create or pick a passkey.
 *
 * @returns The window content
 */
function PasskeyWindow() {
  const [loaded, setLoaded] = useState<
    | { status: "loading" }
    | { status: "expired" }
    | { status: "ready"; view: PasskeyRequestView }
  >({ status: "loading" });
  const load = useCallback(async () => {
    const found = await call<PasskeyRequestView | undefined>({
      type: "passkey-request",
      id: requestId,
    });

    setLoaded(
      found === undefined
        ? { status: "expired" }
        : { status: "ready", view: found },
    );
  }, []);

  const armed = useArmedAfterFocus(500);

  useEffect(() => {
    void load();
  }, [load]);

  if (loaded.status === "loading") {
    return <p className="body muted">Loading…</p>;
  }

  if (loaded.status === "expired") {
    return (
      <p className="body muted">
        This request has expired. You can close this window.
      </p>
    );
  }

  const { view } = loaded;

  return (
    <>
      <header>
        <span className="brand">🔑 keymember</span>
        <span className="small muted">{view.origin}</span>
      </header>
      <div className="body">
        {!view.unlocked || view.needsReverify ? (
          <Verify reverify={view.unlocked} onDone={load} />
        ) : (
          // Choices arm only after the window has had focus for a moment, so a click aimed at the
          // page underneath (a double-click trap) cannot land on them
          <fieldset
            disabled={!armed}
            style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}
          >
            {view.kind === "create" ? (
              <CreateChoice view={view} />
            ) : (
              <GetChoice view={view} />
            )}
          </fieldset>
        )}
        <div className="row">
          <button
            type="button"
            className="btn btn-ghost btn-small"
            onClick={() => {
              void decide({ action: "fallback" });
            }}
          >
            Use another device or browser
          </button>
          <button
            type="button"
            className="btn btn-ghost btn-small"
            onClick={() => {
              void decide({ action: "cancel" });
            }}
          >
            Cancel
          </button>
        </div>
      </div>
    </>
  );
}

/**
 * ### useArmedAfterFocus
 *
 * `true` once the window has been focused for `delayMs`; drops back to `false` on blur.
 *
 * @param delayMs Delay after focus
 * @returns Whether choices may be clicked
 */
function useArmedAfterFocus(delayMs: number): boolean {
  const [armed, setArmed] = useState(false);

  useEffect(() => {
    let timer: number | undefined;
    const arm = (): void => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        setArmed(true);
      }, delayMs);
    };
    const disarm = (): void => {
      window.clearTimeout(timer);
      setArmed(false);
    };

    if (document.hasFocus()) {
      arm();
    }

    window.addEventListener("focus", arm);
    window.addEventListener("blur", disarm);

    return () => {
      window.clearTimeout(timer);
      window.removeEventListener("focus", arm);
      window.removeEventListener("blur", disarm);
    };
  }, [delayMs]);

  return armed;
}

/**
 * ### Verify
 *
 * Asks for the account password: to unlock, or to verify the user again when the site requires it.
 *
 * @param props Whether this is a re-verification, and the completion handler
 * @returns The form
 */
function Verify({
  reverify,
  onDone,
}: {
  reverify: boolean;
  onDone: () => Promise<void>;
}) {
  const [state, setState] = useState<ExtensionState | undefined>(undefined);
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    void call<ExtensionState>({ type: "state" }).then(setState);
  }, []);

  if (state === undefined) {
    return null;
  }

  return (
    <form
      className="body"
      style={{ padding: 0 }}
      onSubmit={(event: SyntheticEvent) => {
        event.preventDefault();
        setError("");
        void call<{ ok: boolean; message?: string }>({
          type: "unlock",
          email: state.email ?? "",
          password,
          ...(state.knownDevice ? {} : { secretKey }),
        }).then(async (result) => {
          if (result.ok) {
            await onDone();
          } else {
            setError(result.message ?? "Couldn't unlock.");
          }
        });
      }}
    >
      <p>
        {reverify
          ? "This site asks you to confirm it's you. Enter your password again."
          : "Unlock keymember to use a passkey."}
      </p>
      <p className="small muted">{state.email}</p>
      <div className="field">
        <label htmlFor="password">Password</label>
        <input
          id="password"
          type="password"
          required
          autoFocus
          value={password}
          onChange={(event) => {
            setPassword(event.target.value);
          }}
        />
      </div>
      {state.knownDevice ? null : (
        <div className="field">
          <label htmlFor="secret-key">Secret Key</label>
          <input
            id="secret-key"
            required
            value={secretKey}
            onChange={(event) => {
              setSecretKey(event.target.value);
            }}
          />
        </div>
      )}
      <p className="error" role="alert">
        {error}
      </p>
      <button type="submit" className="btn btn-primary">
        Continue
      </button>
    </form>
  );
}

/**
 * ### CreateChoice
 *
 * Saves a new passkey on an existing login for the site, or as a new item.
 *
 * @param props Request view
 * @returns The choice form
 */
function CreateChoice({ view }: { view: PasskeyRequestView }) {
  const [target, setTarget] = useState(
    view.targets[0] === undefined
      ? `vault:${view.vaults[0]?.id ?? ""}`
      : `item:${view.targets[0].itemId}`,
  );
  const [busy, setBusy] = useState(false);

  return (
    <>
      <p>
        Create a passkey
        {view.userName === undefined ? null : (
          <>
            {" "}
            for <strong>{view.userName}</strong>
          </>
        )}{" "}
        on <strong>{view.rpId}</strong>?
      </p>
      <div className="field">
        <label htmlFor="target">Save to</label>
        <select
          id="target"
          value={target}
          onChange={(event) => {
            setTarget(event.target.value);
          }}
        >
          {view.targets.map((item) => (
            <option key={item.itemId} value={`item:${item.itemId}`}>
              Existing item: {item.title}
              {item.username === undefined ? "" : ` (${item.username})`}
            </option>
          ))}
          {view.vaults.map((vault) => (
            <option key={vault.id} value={`vault:${vault.id}`}>
              New item in {vault.name}
            </option>
          ))}
        </select>
      </div>
      <button
        type="button"
        className="btn btn-primary"
        disabled={busy || target.endsWith(":")}
        onClick={() => {
          setBusy(true);

          const [kind, id] = target.split(":");

          void decide({
            action: "create",
            ...(kind === "item" ? { itemId: id } : { vaultId: id }),
          });
        }}
      >
        Save passkey
      </button>
    </>
  );
}

/**
 * ### GetChoice
 *
 * Picks which stored passkey signs in.
 *
 * @param props Request view
 * @returns The list of passkeys
 */
function GetChoice({ view }: { view: PasskeyRequestView }) {
  if (view.candidates.length === 0) {
    return <p className="muted">No passkeys saved for {view.rpId}.</p>;
  }

  return (
    <>
      <p>
        Choose a passkey to sign in to <strong>{view.rpId}</strong>.
      </p>
      <ul className="items">
        {view.candidates.map((candidate) => (
          <li key={candidate.credentialId}>
            <button
              type="button"
              className="item"
              style={{
                width: "100%",
                textAlign: "left",
                cursor: "pointer",
                font: "inherit",
                color: "inherit",
              }}
              onClick={() => {
                void decide({
                  action: "use",
                  itemId: candidate.itemId,
                  credentialId: candidate.credentialId,
                });
              }}
            >
              <div className="title">{candidate.userName}</div>
              <div className="small muted">{candidate.title}</div>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}

const root = document.getElementById("root");

if (root !== null) {
  createRoot(root).render(
    <StrictMode>
      <PasskeyWindow />
    </StrictMode>,
  );
}
