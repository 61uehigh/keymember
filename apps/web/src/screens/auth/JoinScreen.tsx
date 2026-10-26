import { logIn, signUp } from "@keymember/client";
import type { InviteLink, Session } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { useEffect, useState } from "react";
import type { SyntheticEvent } from "react";

import { transport } from "../../lib/api.js";
import { useAppState } from "../../lib/AppState.js";
import { clearSensitiveParams, navigate } from "../../lib/router.js";
import { useSsoPrompt } from "../../ui/SsoPrompt.js";
import { ErrorText, Field, useAction } from "../../ui/primitives.js";
import {
  AuthCard,
  MIN_PASSWORD_LENGTH,
  PinOwner,
  SecretKeyReveal,
} from "./AuthCard.js";
import { checkNewPassword, deviceName } from "./passwords.js";

/**
 * ### JoinScreen
 *
 * Accepts an invite. A complete link (`#/join?invite=…&email=…&secret=…&roots=…`) also proves
 * the new keys to the inviting admin and pins the organisation's roots, so nobody compares a
 * fingerprint; a token typed in by hand falls back to that comparison.
 *
 * @param props Invite token and email from the address, and the whole link when complete
 * @returns The join screen
 */
export function JoinScreen({
  initialToken,
  initialEmail,
  link,
}: {
  initialToken: string;
  initialEmail: string;
  link: InviteLink | undefined;
}) {
  const { device, updateDevice, unlock, trust } = useAppState();
  // The address is cleared right after the first render, so keep the link from it
  const [invite] = useState(link);
  const [form, setForm] = useState({
    token: initialToken,
    email: initialEmail,
    name: "",
    password: "",
    confirm: "",
  });
  const [step, setStep] = useState<
    | { kind: "form" }
    | { kind: "reveal" | "pin"; session: Session; secretKey: SecretKey }
  >({
    kind: "form",
  });
  const action = useAction();
  const sso = useSsoPrompt();

  useEffect(() => {
    clearSensitiveParams("/join");
  }, []);

  const submit = (event: SyntheticEvent): void => {
    event.preventDefault();
    void action.run(async () => {
      checkNewPassword(form.password, form.confirm);

      const email = form.email.trim().toLowerCase();
      const account = await signUp(
        transport,
        form.token.trim(),
        { email, name: form.name.trim(), password: form.password },
        invite?.secret,
      );
      const session = await sso.run((handler) =>
        logIn(transport, {
          email,
          password: form.password,
          secretKey: account.secretKey,
          deviceId: device.deviceId,
          deviceName: deviceName(),
          sso: handler,
        }),
      );

      const signedUp = {
        ...device,
        email,
        secretKey: formatSecretKey(account.secretKey),
      };

      updateDevice(signedUp);

      if (invite !== undefined) {
        await trust.adoptRoots(session, invite.roots);
      }

      setStep({ kind: "reveal", session, secretKey: account.secretKey });
    });
  };

  if (step.kind === "reveal") {
    return (
      <AuthCard title="You're in">
        <SecretKeyReveal
          email={step.session.user.email}
          secretKey={step.secretKey}
          onContinue={() => {
            if (invite === undefined) {
              setStep({ ...step, kind: "pin" });

              return;
            }

            unlock(step.session);
            navigate("/vault");
          }}
        />
      </AuthCard>
    );
  }

  if (step.kind === "pin") {
    return (
      <AuthCard title="Verify organization">
        <PinOwner
          session={step.session}
          onDone={() => {
            unlock(step.session);
            navigate("/vault");
          }}
        />
      </AuthCard>
    );
  }

  const set =
    (key: keyof typeof form) => (event: { target: { value: string } }) => {
      setForm({ ...form, [key]: event.target.value });
    };

  return (
    <AuthCard
      title="Accept invite"
      lead="Create your account with the invite an admin sent you."
    >
      <form className="stack" onSubmit={submit}>
        {invite === undefined ? (
          <Field
            label="Invite token"
            required
            value={form.token}
            onChange={set("token")}
            autoComplete="off"
          />
        ) : null}
        <Field
          label="Email"
          type="email"
          required
          readOnly={invite !== undefined}
          value={form.email}
          onChange={set("email")}
          autoComplete="email"
        />
        <Field
          label="Name"
          required
          value={form.name}
          onChange={set("name")}
          autoComplete="name"
        />
        <Field
          label="Password"
          type="password"
          required
          value={form.password}
          onChange={set("password")}
          autoComplete="new-password"
          hint={`At least ${String(MIN_PASSWORD_LENGTH)} characters. Never sent to the server.`}
        />
        <Field
          label="Confirm password"
          type="password"
          required
          value={form.confirm}
          onChange={set("confirm")}
          autoComplete="new-password"
        />
        <ErrorText message={action.error} />
        {sso.prompt}
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy}
        >
          {action.busy ? "Generating keys…" : "Join"}
        </button>
      </form>
    </AuthCard>
  );
}
