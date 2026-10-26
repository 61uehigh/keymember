import { renderEmergencyKit } from "@keymember/client";
import type { OwnerCheck, TrustedSession } from "@keymember/client";
import { formatSecretKey } from "@keymember/core";
import type { SecretKey } from "@keymember/core";
import { useEffect, useState } from "react";
import type { ReactNode } from "react";

import { useAppState } from "../../lib/AppState.js";
import { downloadBytes, ErrorText, useAction } from "../../ui/primitives.js";

export const MIN_PASSWORD_LENGTH = 12;

/**
 * ### AuthCard
 *
 * Centered card used by every signed-out screen.
 *
 * @param props Heading, optional lead text and content
 * @returns The card layout
 */
export function AuthCard({
  title,
  lead,
  children,
}: {
  title: string;
  lead?: ReactNode;
  children: ReactNode;
}) {
  return (
    <main className="centered">
      <div className="narrow stack">
        <p className="brand">🔑 keymember</p>
        <div className="card stack">
          <h1>{title}</h1>
          {lead === undefined ? null : <p className="muted">{lead}</p>}
          {children}
        </div>
      </div>
    </main>
  );
}

/**
 * ### SecretKeyReveal
 *
 * Shows a new Secret Key once, offers the Emergency Kit PDF, and only lets the user
 * continue after they confirm they stored it.
 *
 * @param props Account details and the continue handler
 * @returns The reveal step
 */
export function SecretKeyReveal({
  email,
  secretKey,
  onContinue,
}: {
  email: string;
  secretKey: SecretKey;
  onContinue: () => void;
}) {
  const [saved, setSaved] = useState(false);
  const download = useAction();

  return (
    <div className="stack">
      <p>
        Your account opens only with both your password and the{" "}
        <strong>Secret Key</strong> below. No one, not even an admin, can give
        it to you again.
      </p>
      <div className="secret-key" aria-label="Secret Key">
        {formatSecretKey(secretKey)}
      </div>
      <button
        type="button"
        className="btn"
        disabled={download.busy}
        onClick={() =>
          void download.run(async () => {
            const pdf = await renderEmergencyKit({
              serverUrl: location.origin,
              email,
              secretKey,
              createdAt: new Date(),
            });

            downloadBytes(
              pdf,
              `keymember-emergency-kit-${email}.pdf`,
              "application/pdf",
            );
          })
        }
      >
        Download Emergency Kit PDF
      </button>
      <ErrorText message={download.error} />
      <p className="hint">
        Print it, keep it somewhere offline like a desk drawer, then delete the
        downloaded file.
      </p>
      <label className="row">
        <input
          type="checkbox"
          checked={saved}
          onChange={(event) => {
            setSaved(event.target.checked);
          }}
        />
        I've stored my Secret Key somewhere safe
      </label>
      <button
        type="button"
        className="btn btn-primary"
        disabled={!saved}
        onClick={onContinue}
      >
        Continue
      </button>
    </div>
  );
}

/**
 * ### PinOwner
 *
 * Asks the user to compare the owner's fingerprint, received out of band, before pinning it
 * as this browser's trust root. Without a pinned root the app verifies nobody.
 *
 * @param props Session to read the directory with, and the finish handler
 * @returns The pinning step
 */
export function PinOwner({
  session,
  onDone,
}: {
  session: OwnerCheck & TrustedSession;
  onDone: () => void;
}) {
  const { trust } = useAppState();
  const [owner, setOwner] = useState<
    | {
        userId: string;
        email: string;
        signingPublicKey: Uint8Array;
        fingerprint: string;
      }
    | undefined
  >(undefined);
  const load = useAction();
  const pin = useAction();
  const { run } = load;

  useEffect(() => {
    void run(async () => {
      const [candidate] = await session.ownerCandidates();

      if (candidate === undefined) {
        throw new Error("The server didn't return the owner's details.");
      }

      setOwner(candidate);
    });
  }, [session, run]);

  return (
    <div className="stack">
      <p>
        Before this browser can trust the organization, you need to verify the
        owner's key once. Check that the fingerprint below matches the one the
        owner gave you.
      </p>
      {owner === undefined ? (
        <p className="muted">Loading…</p>
      ) : (
        <div className="stack">
          <p className="small muted">{owner.email}</p>
          <div className="secret-key">{owner.fingerprint}</div>
        </div>
      )}
      <ErrorText message={load.error ?? pin.error} />
      <p className="small muted">
        Your fingerprint: <code>{session.fingerprint}</code> — an admin needs it
        to verify you.
      </p>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={owner === undefined || pin.busy}
          onClick={() => {
            void pin.run(async () => {
              if (owner !== undefined) {
                await trust.pinOwner(session, owner.userId, owner.fingerprint);
              }

              onDone();
            });
          }}
        >
          They match
        </button>
        <button type="button" className="btn btn-ghost" onClick={onDone}>
          Verify later
        </button>
      </div>
    </div>
  );
}
