import { renderEmergencyKit } from "@keymember/client";
import { parseSecretKey } from "@keymember/core";
import QRCode from "qrcode";
import { useState } from "react";

import { useAppState, useSession } from "../lib/AppState.js";
import { forgetDevice } from "../lib/deviceStore.js";
import {
  downloadBytes,
  ErrorText,
  Field,
  useAction,
  useToast,
} from "../ui/primitives.js";

/**
 * ### AccountScreen
 *
 * The user's own account: fingerprint, two-factor login, password and Emergency Kit.
 *
 * @returns The account screen
 */
export function AccountScreen() {
  const session = useSession();
  const { device, lock } = useAppState();
  const kit = useAction();

  return (
    <div className="page-inner stack">
      <h1>Account</h1>
      <section className="card stack">
        <h2>{session.user.name}</h2>
        <p className="muted">{session.user.email}</p>
        <div className="stack">
          <span className="small muted">
            Your key fingerprint (an admin compares it when verifying you)
          </span>
          <div className="secret-key">{session.fingerprint}</div>
        </div>
        {session.user.status === "accepted" ? (
          <p className="notice small">
            An admin hasn't verified your key yet. Give the fingerprint above to
            an admin directly.
          </p>
        ) : null}
      </section>

      <TotpSection />
      <PasswordSection />

      <section className="card stack">
        <h2>Emergency Kit</h2>
        <p className="muted small">
          Download a fresh copy of the PDF with the Secret Key you need to sign
          in on a new device.
        </p>
        <div className="row wrap">
          <button
            type="button"
            className="btn"
            disabled={kit.busy}
            onClick={() =>
              void kit.run(async () => {
                const secretKey =
                  device.secretKey === undefined
                    ? undefined
                    : parseSecretKey(device.secretKey);

                if (secretKey === undefined) {
                  throw new Error("This browser doesn't have your Secret Key.");
                }

                downloadBytes(
                  await renderEmergencyKit({
                    serverUrl: location.origin,
                    email: session.user.email,
                    secretKey,
                    createdAt: new Date(),
                  }),
                  `keymember-emergency-kit-${session.user.email}.pdf`,
                  "application/pdf",
                );
              })
            }
          >
            Download Emergency Kit
          </button>
          <button
            type="button"
            className="btn btn-danger"
            onClick={() => {
              if (
                window.confirm(
                  "This removes the Secret Key from this browser and locks it. You'll need your Secret Key the next time you sign in.",
                )
              ) {
                forgetDevice();
                lock();
                location.reload();
              }
            }}
          >
            Remove account from this browser
          </button>
        </div>
        <ErrorText message={kit.error} />
      </section>
    </div>
  );
}

/**
 * ### TotpSection
 *
 * Enrols two-factor login: shows a QR code, then confirms with a code from the app.
 *
 * @returns The section
 */
function TotpSection() {
  const session = useSession();
  const { touch } = useAppState();
  const [setup, setSetup] = useState<
    { secret: string; qr: string } | undefined
  >(undefined);
  const [code, setCode] = useState("");
  const [enabled, setEnabled] = useState(false);
  const action = useAction();

  return (
    <section className="card stack">
      <h2>Two-factor authentication</h2>
      {enabled ? (
        <p className="badge badge-ok">On</p>
      ) : setup === undefined ? (
        <>
          <p className="muted small">
            Confirm each sign-in a second time with an OTP app such as Google
            Authenticator or 1Password.
          </p>
          <button
            type="button"
            className="btn"
            disabled={action.busy}
            onClick={() =>
              void action.run(async () => {
                const { secret, uri } = await session.setupTotp();

                setSetup({
                  secret,
                  qr: await QRCode.toDataURL(uri, { margin: 1, width: 200 }),
                });
              })
            }
          >
            Set up
          </button>
        </>
      ) : (
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            void action.run(async () => {
              await session.confirmTotp(code.trim());
              setEnabled(true);
              touch();
            });
          }}
        >
          <img
            src={setup.qr}
            width={200}
            height={200}
            alt="QR code to scan with your OTP app"
          />
          <p className="small muted">
            Can't scan it? Enter this instead: <code>{setup.secret}</code>
          </p>
          <Field
            label="6-digit code from the app"
            inputMode="numeric"
            pattern="\d{6}"
            required
            value={code}
            onChange={(event) => {
              setCode(event.target.value);
            }}
            autoComplete="one-time-code"
          />
          <button
            type="submit"
            className="btn btn-primary"
            disabled={action.busy}
          >
            Verify
          </button>
        </form>
      )}
      <ErrorText message={action.error} />
    </section>
  );
}

/**
 * ### PasswordSection
 *
 * Changes the account password. Other devices are logged out.
 *
 * @returns The section
 */
function PasswordSection() {
  const session = useSession();
  const [form, setForm] = useState({ current: "", next: "", confirm: "" });
  const action = useAction();
  const toast = useToast();

  return (
    <form
      className="card stack"
      onSubmit={(event) => {
        event.preventDefault();
        void action.run(async () => {
          if (form.next.length < 12) {
            throw new Error("New password must be at least 12 characters.");
          }

          if (form.next !== form.confirm) {
            throw new Error("New passwords don't match.");
          }

          await session.changePassword(form.current, form.next);
          setForm({ current: "", next: "", confirm: "" });
          toast("Password changed. Your other devices need to sign in again.");
        });
      }}
    >
      <h2>Change password</h2>
      <Field
        label="Current password"
        type="password"
        required
        value={form.current}
        onChange={(event) => {
          setForm({ ...form, current: event.target.value });
        }}
        autoComplete="current-password"
      />
      <Field
        label="New password"
        type="password"
        required
        value={form.next}
        onChange={(event) => {
          setForm({ ...form, next: event.target.value });
        }}
        autoComplete="new-password"
      />
      <Field
        label="Confirm new password"
        type="password"
        required
        value={form.confirm}
        onChange={(event) => {
          setForm({ ...form, confirm: event.target.value });
        }}
        autoComplete="new-password"
      />
      <ErrorText message={action.error} />
      <div>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy}
        >
          Change
        </button>
      </div>
    </form>
  );
}
