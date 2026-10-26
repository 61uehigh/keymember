import type {
  DirectoryMember,
  OrgAdmin,
  OrganisationAdministration,
} from "@keymember/client";
import { useEffect, useState } from "react";

import { ErrorText, useAction } from "../../ui/primitives.js";

const ACTION_LABELS: Readonly<Record<string, string>> = {
  "org.bootstrapped": "Organization created",
  "user.signed_up": "Signed up",
  "auth.login": "Signed in",
  "auth.login_failed": "Sign-in failed",
  "auth.refresh_reuse_detected": "Token reuse detected",
  "auth.sso_verified": "Company account verified",
  "auth.sso_failed": "Company account verification failed",
  "auth.sso_revoked": "Signed out: company account suspended",
  "account.totp_enabled": "Two-factor authentication enabled",
  "account.totp_replace_locked": "Authenticator app replacement blocked",
  "account.password_changed": "Password changed",
  "org.invite_created": "Invite created",
  "org.member_confirmed": "Member verified",
  "org.member_suspended": "Member suspended",
  "org.recovery_key_set": "Recovery key set",
  "org.policy_updated": "Policy changed",
  "vault.created": "Vault created",
  "vault.access_granted": "Vault shared",
  "vault.access_revoked": "Vault access revoked",
  "vault.key_rotated": "Vault key rotated",
  "item.created": "Item created",
  "item.updated": "Item updated",
  "item.deleted": "Item deleted",
  "recovery.requested": "Recovery requested",
  "recovery.approved": "Recovery approved",
  "recovery.rekeyed": "Recovery re-keyed",
  "recovery.completed": "Recovery completed",
  "recovery.cancelled": "Recovery cancelled",
  "group.created": "Group created",
  "group.member_added": "Group member added",
  "group.rotated": "Group key rotated",
  "group.deleted": "Group deleted",
  "share.created": "Share link created",
  "share.opened": "Share link opened",
  "share.revoked": "Share link revoked",
};

/**
 * ### AuditTab
 *
 * Recent audit events.
 *
 * @param props Session and directory for resolving names
 * @returns The tab content
 */
export function AuditTab({
  session,
  members,
}: {
  session: OrganisationAdministration;
  members: ReadonlyArray<DirectoryMember>;
}) {
  const [events, setEvents] = useState<
    Awaited<ReturnType<OrgAdmin["auditLog"]>>
  >([]);
  const action = useAction();
  const { run } = action;

  useEffect(() => {
    void run(async () => {
      setEvents(await session.orgAdmin().auditLog(200));
    });
  }, [run, session]);

  const nameOf = (userId: string | null): string =>
    userId === null
      ? "-"
      : (members.find((member) => member.userId === userId)?.email ??
        userId.slice(0, 8));

  return (
    <div className="table-scroll">
      <ErrorText message={action.error} />
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Action</th>
            <th>Actor</th>
            <th>Target</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.id}>
              <td className="small" style={{ whiteSpace: "nowrap" }}>
                {new Date(event.at).toLocaleString(undefined)}
              </td>
              <td>{ACTION_LABELS[event.action] ?? event.action}</td>
              <td className="small">{nameOf(event.actorId)}</td>
              <td className="small muted">{nameOf(event.targetId)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
