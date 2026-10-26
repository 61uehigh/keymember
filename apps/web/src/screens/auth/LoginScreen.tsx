import { logInDevice } from "@keymember/client";
import type { Session } from "@keymember/client";
import { useEffect, useRef, useState } from "react";
import type { SyntheticEvent } from "react";

import { useAppState } from "../../lib/AppState.js";
import { navigate } from "../../lib/router.js";
import { useSsoPrompt } from "../../ui/SsoPrompt.js";
import { ErrorText, Field, useAction } from "../../ui/primitives.js";
import { AuthCard, PinOwner } from "./AuthCard.js";
import { deviceName } from "./passwords.js";

/**
 * ### PENDING_LOGIN_MS
 *
 * How long a login may wait at the owner check before it is dropped, like the idle lock.
 */
const PENDING_LOGIN_MS = 15 * 60 * 1000;

/**
 * ### LoginScreen
 *
 * Unlocks the vault. Asks for the Secret Key only when this browser does not remember it,
 * and for a two-factor code only when the server requires one.
 *
 * @returns The login screen
 */
export function LoginScreen() {
  const { device, updateDevice, unlock, trust } = useAppState();
  const [email, setEmail] = useState(device.email ?? "");
  const [password, setPassword] = useState("");
  const [secretKeyText, setSecretKeyText] = useState(device.secretKey ?? "");
  const [totp, setTotp] = useState<string | undefined>(undefined);
  const [remember, setRemember] = useState(true);
  const [pending, setPending] = useState<Session | undefined>(undefined);
  const pendingHandover = useRef<() => void>(() => undefined);
  const scheduledAbandon = useRef<number | undefined>(undefined);
  const action = useAction();
  const sso = useSsoPrompt();
  const knownDevice = device.secretKey !== undefined;

  // A login waiting for the owner check holds the keys; drop it if the user walks away from it
  useEffect(() => {
    if (pending === undefined) {
      return undefined;
    }

    window.clearTimeout(scheduledAbandon.current);

    const state = { handedOver: false };
    const abandon = (): void => {
      if (!state.handedOver) {
        state.handedOver = true;
        // Best effort, as when locking: the keys leave memory either way
        void pending.logOut().catch(() => undefined);
        setPending(undefined);
      }
    };
    const timer = window.setTimeout(abandon, PENDING_LOGIN_MS);

    pendingHandover.current = () => {
      state.handedOver = true;
    };

    return () => {
      window.clearTimeout(timer);
      // Deferred, so StrictMode's immediate re-run (which cancels it above) keeps the login
      scheduledAbandon.current = window.setTimeout(abandon, 0);
    };
  }, [pending]);

  const submit = (event: SyntheticEvent): void => {
    event.preventDefault();
    void action.run(async () => {
      // The same login every app uses: email normalised, Secret Key checked, errors in Korean
      const login = await sso.run((handler) =>
        logInDevice(
          {
            serverUrl: location.origin,
            deviceId: device.deviceId,
            deviceName: deviceName(),
          },
          {
            email,
            password,
            secretKey: secretKeyText,
            ...(totp === undefined ? {} : { totp }),
          },
          handler,
        ),
      );

      if (!login.ok) {
        if (login.code === "totp_required") {
          setTotp("");

          return;
        }

        throw new Error(login.message);
      }

      const { session } = login;
      const normalizedEmail = login.email;
      const { secretKey: _previous, ...rest } = device;
      const next = remember
        ? { ...device, email: normalizedEmail, secretKey: login.secretKey }
        : { ...rest, email: normalizedEmail };

      updateDevice(next);
      setPassword("");

      if (session.recoveryCancelled) {
        window.alert(
          "Someone had started recovering this account. Because you just signed in, that recovery was cancelled. Check with your admin.",
        );
      }

      // Without pinned or saved roots, the user compares the owner's fingerprint first
      if (!(await trust.afterUnlock(session))) {
        setPending(session);
      } else {
        unlock(session);
        navigate("/vault");
      }
    });
  };

  if (pending !== undefined) {
    return (
      <AuthCard title="Verify organization">
        <PinOwner
          session={pending}
          onDone={() => {
            pendingHandover.current();
            unlock(pending);
            navigate("/vault");
          }}
        />
      </AuthCard>
    );
  }

  return (
    <AuthCard title="Unlock">
      <form className="stack" onSubmit={submit}>
        <Field
          label="Email"
          type="email"
          required
          value={email}
          onChange={(event) => {
            setEmail(event.target.value);
          }}
          autoComplete="username"
        />
        <Field
          label="Password"
          type="password"
          required
          autoFocus={knownDevice}
          value={password}
          onChange={(event) => {
            setPassword(event.target.value);
          }}
          autoComplete="current-password"
        />
        {knownDevice ? null : (
          <Field
            label="Secret Key"
            required
            value={secretKeyText}
            onChange={(event) => {
              setSecretKeyText(event.target.value);
            }}
            autoComplete="off"
            spellCheck={false}
            hint="This is your first sign-in on this browser. Enter the value starting with K1- from your Emergency Kit."
          />
        )}
        {knownDevice ? null : (
          <label className="row small">
            <input
              type="checkbox"
              checked={remember}
              onChange={(event) => {
                setRemember(event.target.checked);
              }}
            />
            Remember Secret Key on this browser (turn off on shared computers)
          </label>
        )}
        {totp === undefined ? null : (
          <Field
            label="Two-factor code"
            inputMode="numeric"
            pattern="\d{6}"
            required
            autoFocus
            value={totp}
            onChange={(event) => {
              setTotp(event.target.value);
            }}
            autoComplete="one-time-code"
          />
        )}
        <ErrorText message={action.error} />
        {sso.prompt}
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy}
        >
          {action.busy ? "Unlocking…" : "Unlock"}
        </button>
        {knownDevice ? (
          <button
            type="button"
            className="btn btn-ghost btn-small"
            onClick={() => {
              updateDevice({ deviceId: device.deviceId, roots: {} });
              setSecretKeyText("");
            }}
          >
            Sign in to a different account (forget this browser's Secret Key)
          </button>
        ) : null}
      </form>
    </AuthCard>
  );
}
