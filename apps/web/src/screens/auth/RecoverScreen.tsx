import { logIn, recoverAccount, recoveryInfo } from "@keymember/client";
import type { Session } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { useEffect, useState } from "react";

import { transport } from "../../lib/api.js";
import { useAppState } from "../../lib/AppState.js";
import { clearSensitiveParams, navigate } from "../../lib/router.js";
import { useSsoPrompt } from "../../ui/SsoPrompt.js";
import { ErrorText, Field, useAction } from "../../ui/primitives.js";
import { AuthCard, PinOwner, SecretKeyReveal } from "./AuthCard.js";
import { checkNewPassword, deviceName } from "./passwords.js";

/**
 * ### RecoverScreen
 *
 * Member side of an account recovery (`#/recover?token=…`): sets a new password and
 * receives a new Secret Key, then waits for an admin to certify the new keys.
 *
 * @param props Recovery token from the link
 * @returns The recovery screen
 */
export function RecoverScreen({ initialToken }: { initialToken: string }) {
  const { device, updateDevice, unlock, trust } = useAppState();
  const [token, setToken] = useState(initialToken);
  const [info, setInfo] = useState<
    { email: string; orgName: string } | undefined
  >(undefined);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [done, setDone] = useState<
    | { session: Session; secretKey: SecretKey; step: "reveal" | "pin" }
    | undefined
  >(undefined);
  const action = useAction();
  const finish = useAction();
  const sso = useSsoPrompt();

  useEffect(() => {
    clearSensitiveParams("/recover");
  }, []);

  /**
   * ### enter
   *
   * Opens the vault with the recovered session.
   *
   * @param session Session with the new keys
   */
  const enter = (session: Session): void => {
    unlock(session);
    navigate("/account");
  };

  if (done?.step === "pin") {
    return (
      <AuthCard title="Verify organization">
        <PinOwner
          session={done.session}
          onDone={() => {
            enter(done.session);
          }}
        />
      </AuthCard>
    );
  }

  if (done !== undefined) {
    return (
      <AuthCard title="New Secret Key">
        <SecretKeyReveal
          email={done.session.user.email}
          secretKey={done.secretKey}
          onContinue={() => {
            window.alert(
              `Send your new fingerprint ${done.session.fingerprint} to your admin. Once they verify it and finish the recovery, your vaults will appear again.`,
            );
            // Re-keying dropped the roots saved with the old key; without roots on this device
            // the restored vaults would never show, so the owner is confirmed again first
            void finish.run(async () => {
              if (await trust.afterUnlock(done.session)) {
                enter(done.session);
              } else {
                setDone({ ...done, step: "pin" });
              }
            });
          }}
        />
        <ErrorText message={finish.error} />
      </AuthCard>
    );
  }

  return (
    <AuthCard
      title="Account recovery"
      lead="Use a recovery token approved by two admins to set a new password and Secret Key."
    >
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            if (info === undefined) {
              setInfo(await recoveryInfo(transport, token.trim()));

              return;
            }

            checkNewPassword(password, confirm);

            const account = await recoverAccount(
              transport,
              token.trim(),
              password,
            );
            const session = await sso.run((handler) =>
              logIn(transport, {
                email: account.email,
                password,
                secretKey: account.secretKey,
                deviceId: device.deviceId,
                deviceName: deviceName(),
                sso: handler,
              }),
            );

            updateDevice({
              ...device,
              email: account.email,
              secretKey: formatSecretKey(account.secretKey),
            });
            setDone({ session, secretKey: account.secretKey, step: "reveal" });
          });
        }}
      >
        <Field
          label="Recovery token"
          required
          value={token}
          readOnly={info !== undefined}
          onChange={(event) => {
            setToken(event.target.value);
          }}
          autoComplete="off"
        />
        {info === undefined ? null : (
          <>
            <p className="notice">
              Recovering <strong>{info.email}</strong> in{" "}
              <strong>{info.orgName}</strong>. Personal data that only your old
              password could open can't be restored.
            </p>
            <Field
              label="New password"
              type="password"
              required
              value={password}
              onChange={(event) => {
                setPassword(event.target.value);
              }}
              autoComplete="new-password"
            />
            <Field
              label="Confirm new password"
              type="password"
              required
              value={confirm}
              onChange={(event) => {
                setConfirm(event.target.value);
              }}
              autoComplete="new-password"
            />
          </>
        )}
        <ErrorText message={action.error} />
        {sso.prompt}
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy}
        >
          {info === undefined
            ? "Check token"
            : action.busy
              ? "Generating keys…"
              : "Recover"}
        </button>
      </form>
    </AuthCard>
  );
}
