import { useEffect, useState } from "react";

import type { ExtensionState } from "../../shared/messages.js";
import { call } from "../background.js";
import { Shell } from "./Shell.js";
import { useAsync } from "../useAsync.js";

/**
 * ### PinOwner
 *
 * Asks the user to compare the owner's fingerprint before trusting it.
 *
 * @param props Completion handler; receives the new state, or nothing when skipped
 * @returns The pinning screen
 */
export function PinOwner({
  onDone,
}: {
  onDone: (state?: ExtensionState) => void;
}) {
  const [owner, setOwner] = useState<
    | { status: "loading" }
    | { status: "missing" }
    | {
        status: "ready";
        userId: string;
        email: string;
        fingerprint: string;
      }
  >({ status: "loading" });
  const { busy, error, run } = useAsync();

  useEffect(() => {
    run(async () => {
      const [candidate] = await call<
        Array<{ userId: string; email: string; fingerprint: string }>
      >({
        type: "owner-candidates",
      });

      setOwner(
        candidate === undefined
          ? { status: "missing" }
          : { status: "ready", ...candidate },
      );
    });
  }, [run]);

  return (
    <Shell>
      <p>
        To let this browser trust your organization, check that the fingerprint
        below matches the one the owner gave you.
      </p>
      {owner.status === "ready" ? (
        <>
          <p className="small muted">{owner.email}</p>
          <div className="fingerprint">{owner.fingerprint}</div>
        </>
      ) : null}
      {owner.status === "missing" ? (
        <p className="error" role="alert">
          The server didn't return the owner's details. Contact your admin.
        </p>
      ) : null}
      <p className="error" role="alert">
        {error}
      </p>
      <div className="row">
        <button
          type="button"
          className="btn btn-primary"
          disabled={busy || owner.status !== "ready"}
          onClick={() => {
            run(async () => {
              if (owner.status === "ready") {
                onDone(
                  await call<ExtensionState>({
                    type: "pin-owner",
                    userId: owner.userId,
                    fingerprint: owner.fingerprint,
                  }),
                );
              }
            });
          }}
        >
          They match
        </button>
        <button
          type="button"
          className="btn btn-ghost"
          onClick={() => {
            onDone();
          }}
        >
          Later
        </button>
      </div>
    </Shell>
  );
}
