import { useState } from "react";
import type { SyntheticEvent } from "react";

import type { DesktopState, UnlockResult } from "../../shared/ipc.js";
import { Field } from "../Field.js";
import { call } from "../ipc.js";
import { useAction } from "../useAction.js";

/**
 * ### Unlock
 *
 * Unlocks with Touch ID or the password (and Secret Key on a new computer).
 *
 * @param props State and completion handler
 * @returns The form
 */
export function Unlock({
  state,
  onUnlocked,
}: {
  state: DesktopState;
  onUnlocked: (state: DesktopState) => Promise<void>;
}) {
  const [email, setEmail] = useState(state.email ?? "");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [totp, setTotp] = useState<string | undefined>(undefined);
  const [notice, setNotice] = useState("");
  const action = useAction();
  const finish = async (result: UnlockResult): Promise<void> => {
    if (result.ok) {
      // Someone else started recovering this account; the user must hear about it
      if (result.recoveryCancelled) {
        window.alert(
          "Someone had started recovering this account, and signing in just now cancelled it. Check with your admin.",
        );
      }

      await onUnlocked(await call<DesktopState>({ type: "state" }));

      return;
    }

    if (result.code === "totp_required") {
      setTotp("");

      return;
    }

    throw new Error(result.message);
  };

  return (
    <form
      className="stack"
      onSubmit={(event: SyntheticEvent) => {
        event.preventDefault();
        setNotice("");
        action.run(async () => {
          setNotice(
            "If your company account needs to be verified, a browser window opens. Unlocking continues once you finish.",
          );
          await finish(
            await call<UnlockResult>({
              type: "unlock",
              email,
              password,
              ...(state.knownDevice ? {} : { secretKey }),
              ...(totp === undefined ? {} : { totp }),
            }),
          );
          setPassword("");
        });
      }}
    >
      <h1>Unlock</h1>
      <p className="muted small">{state.serverUrl}</p>
      {state.biometricEnabled ? (
        <button
          type="button"
          className="btn btn-primary"
          disabled={action.busy}
          onClick={() => {
            action.run(async () => {
              await finish(
                await call<UnlockResult>({ type: "unlock-biometric" }),
              );
            });
          }}
        >
          Unlock with Touch ID
        </button>
      ) : null}
      <Field
        label="Email"
        id="email"
        type="email"
        required
        value={email}
        onChange={(event) => {
          setEmail(event.target.value);
        }}
      />
      <Field
        label="Password"
        id="password"
        type="password"
        required
        autoFocus
        value={password}
        onChange={(event) => {
          setPassword(event.target.value);
        }}
      />
      {state.knownDevice ? null : (
        <Field
          label="Secret Key"
          id="secret-key"
          required
          placeholder="K1-…"
          value={secretKey}
          onChange={(event) => {
            setSecretKey(event.target.value);
          }}
        />
      )}
      {totp === undefined ? null : (
        <Field
          label="Two-factor authentication code"
          id="totp"
          inputMode="numeric"
          required
          value={totp}
          onChange={(event) => {
            setTotp(event.target.value);
          }}
        />
      )}
      {action.busy && notice !== "" ? (
        <p className="muted small">{notice}</p>
      ) : null}
      <p className="error">{action.error}</p>
      <button type="submit" className="btn btn-primary" disabled={action.busy}>
        {action.busy ? "Verifying…" : "Unlock"}
      </button>
    </form>
  );
}
