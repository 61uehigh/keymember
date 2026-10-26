import { useEffect, useState } from "react";

import { call } from "../ipc.js";
import { useAction } from "../useAction.js";

/**
 * ### OwnerCandidate
 *
 * An owner the server reports, with the fingerprint to compare.
 */
interface OwnerCandidate {
  readonly userId: string;
  readonly email: string;
  readonly fingerprint: string;
}

/**
 * ### PinOwner
 *
 * Compare the owner's fingerprint and pin their key, or postpone it.
 *
 * @param props Completion and postpone handlers
 * @returns The screen
 */
export function PinOwner({
  onDone,
  onLater,
}: {
  onDone: () => Promise<void>;
  onLater: () => void;
}) {
  const [owners, setOwners] = useState<Array<OwnerCandidate> | undefined>(
    undefined,
  );
  const load = useAction();
  const pin = useAction();
  const { run } = load;

  useEffect(() => {
    run(async () => {
      setOwners(
        await call<Array<OwnerCandidate>>({ type: "owner-candidates" }),
      );
    });
  }, [run]);

  const owner = owners?.[0];

  return (
    <div className="stack">
      <h1>Verify organization</h1>
      <p>
        Check that the fingerprint below matches the one the owner gave you.
        This computer trusts the organization only if they match.
      </p>
      {owners === undefined ? (
        <p className="muted">{load.busy ? "Loading…" : ""}</p>
      ) : owner === undefined ? (
        <p className="error">
          The server didn't return the owner's details. Contact your admin.
        </p>
      ) : (
        <>
          <p className="muted small">{owner.email}</p>
          <code className="fingerprint">{owner.fingerprint}</code>
          <button
            type="button"
            className="btn btn-primary"
            disabled={pin.busy}
            onClick={() => {
              pin.run(async () => {
                await call({
                  type: "pin-owner",
                  userId: owner.userId,
                  fingerprint: owner.fingerprint,
                });
                await onDone();
              });
            }}
          >
            They match
          </button>
        </>
      )}
      <button type="button" className="btn btn-ghost" onClick={onLater}>
        Verify later
      </button>
      <p className="error">{load.error || pin.error}</p>
    </div>
  );
}
