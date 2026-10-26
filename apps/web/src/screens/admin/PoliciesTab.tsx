import type {
  OrganisationAdministration,
  OrgPolicies,
} from "@keymember/client";
import { useCallback, useEffect, useState } from "react";

import { ErrorText, useAction } from "../../ui/primitives.js";
import { useSsoPrompt } from "../../ui/SsoPrompt.js";

/**
 * ### PoliciesTab
 *
 * Organisation policies.
 *
 * @param props Session
 * @returns The tab content
 */
export function PoliciesTab({
  session,
}: {
  session: OrganisationAdministration;
}) {
  const [policies, setPolicies] = useState<OrgPolicies | undefined>(undefined);
  const action = useAction();
  const sso = useSsoPrompt();
  const { run } = action;

  const refresh = useCallback(async () => {
    setPolicies(await session.policies());
  }, [session]);

  useEffect(() => {
    void run(refresh);
  }, [run, refresh]);

  return (
    <div className="stack">
      <div className="card stack">
        <label className="row">
          <input
            type="checkbox"
            disabled={policies === undefined || action.busy}
            checked={policies?.requireTotp ?? false}
            onChange={(event) => {
              const next = event.target.checked;

              void action.run(async () => {
                await session.orgAdmin().setRequireTotp(next);
                await refresh();
              });
            }}
          />
          Require two-factor authentication (TOTP)
        </label>
        <p className="hint">
          When on, members who haven't set up two-factor authentication can't
          open any vault until they do.
        </p>
      </div>
      <div className="card stack">
        <label className="row">
          <input
            type="checkbox"
            disabled={
              policies === undefined ||
              !policies.ssoAvailable ||
              (!policies.ssoLinked && !policies.requireSso) ||
              action.busy
            }
            checked={policies?.requireSso ?? false}
            onChange={(event) => {
              const next = event.target.checked;

              if (
                next &&
                !window.confirm(
                  "Make company account verification required? Every login that hasn't been verified will be signed out, and members will have to sign in again and verify their company Google account. Continue?",
                )
              ) {
                return;
              }

              void action.run(async () => {
                await session.orgAdmin().setRequireSso(next);
                await refresh();
              });
            }}
          />
          Require company account verification (SSO)
        </label>
        <p className="hint">
          When on, signing in requires verifying the company Google account in
          addition to the password and Secret Key, and if that Google account is
          suspended, keymember is signed out on every device within 15 minutes.
          Unlocking a vault still uses only the password and Secret Key.
        </p>
        {policies?.ssoAvailable === false ? (
          <p className="hint">
            Google Workspace integration isn't configured on the server
            (KEYMEMBER_OIDC_* environment variables).
          </p>
        ) : null}
        {policies?.ssoAvailable === true && !policies.ssoLinked ? (
          <div className="stack">
            <p className="hint">
              So a misconfiguration can't lock everyone out, first verify your
              current login with your company account before turning this on.
            </p>
            <div>
              <button
                type="button"
                className="btn"
                disabled={action.busy}
                onClick={() => {
                  void action.run(async () => {
                    await sso.run((handler) => session.linkSso(handler));
                    await refresh();
                  });
                }}
              >
                Verify my login with my company account
              </button>
            </div>
          </div>
        ) : null}
        {sso.prompt}
      </div>
      <ErrorText message={action.error} />
    </div>
  );
}
