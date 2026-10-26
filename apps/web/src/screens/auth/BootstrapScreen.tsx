import { bootstrapOrganization, logIn } from "@keymember/client";
import type { Session } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { useState } from "react";
import type { SyntheticEvent } from "react";

import { transport } from "../../lib/api.js";
import { useAppState } from "../../lib/AppState.js";
import { navigate } from "../../lib/router.js";
import { useSsoPrompt } from "../../ui/SsoPrompt.js";
import { ErrorText, Field, useAction } from "../../ui/primitives.js";
import { AuthCard, MIN_PASSWORD_LENGTH, SecretKeyReveal } from "./AuthCard.js";
import { checkNewPassword, deviceName } from "./passwords.js";

/**
 * ### BootstrapScreen
 *
 * First run on an empty server: creates the organisation with the visitor as owner.
 *
 * @returns The bootstrap screen
 */
export function BootstrapScreen() {
  const { device, updateDevice, unlock, trust } = useAppState();
  const [form, setForm] = useState({
    bootstrapToken: "",
    orgName: "",
    name: "",
    email: "",
    password: "",
    confirm: "",
  });
  const [created, setCreated] = useState<
    { session: Session; secretKey: SecretKey } | undefined
  >(undefined);
  const action = useAction();
  const sso = useSsoPrompt();

  const submit = (event: SyntheticEvent): void => {
    event.preventDefault();
    void action.run(async () => {
      checkNewPassword(form.password, form.confirm);

      const email = form.email.trim().toLowerCase();
      const account = await bootstrapOrganization(
        transport,
        form.orgName.trim(),
        {
          email,
          name: form.name.trim(),
          password: form.password,
        },
        form.bootstrapToken.trim(),
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

      await session.orgAdmin().initializeOrganization();
      updateDevice({
        ...device,
        email,
        secretKey: formatSecretKey(account.secretKey),
      });
      // The owner is the organisation's root; saving it spares the owner's other devices a check
      await trust.adoptRoots(
        session,
        new Map([[session.user.id, session.signingPublicKey]]),
      );
      setCreated({ session, secretKey: account.secretKey });
    });
  };

  if (created !== undefined) {
    return (
      <AuthCard title="Organization created">
        <SecretKeyReveal
          email={created.session.user.email}
          secretKey={created.secretKey}
          onContinue={() => {
            unlock(created.session);
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
      title="Create organization"
      lead="As the first user on this server, you create the organization and become its owner."
    >
      <form className="stack" onSubmit={submit}>
        <Field
          label="Bootstrap token"
          required
          value={form.bootstrapToken}
          onChange={set("bootstrapToken")}
          autoComplete="off"
          hint="The token printed in the log when the server first started, or the value you set in KEYMEMBER_BOOTSTRAP_TOKEN."
        />
        <Field
          label="Organization name"
          required
          value={form.orgName}
          onChange={set("orgName")}
          autoComplete="organization"
        />
        <Field
          label="Name"
          required
          value={form.name}
          onChange={set("name")}
          autoComplete="name"
        />
        <Field
          label="Email"
          type="email"
          required
          value={form.email}
          onChange={set("email")}
          autoComplete="email"
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
          {action.busy ? "Generating keys…" : "Create organization"}
        </button>
      </form>
    </AuthCard>
  );
}
