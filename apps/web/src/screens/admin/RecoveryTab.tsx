import type {
  DirectoryMember,
  OrganisationAdministration,
  RecoverySummary,
} from "@keymember/client";
import { useCallback, useEffect, useState } from "react";

import { copySecret } from "../../lib/clipboard.js";
import { ErrorText, useAction, useToast } from "../../ui/primitives.js";

/**
 * ### RecoveryTab
 *
 * Request, approve, complete and cancel account recoveries.
 *
 * @param props Session, directory and refresh callback
 * @returns The tab content
 */
export function RecoveryTab({
  session,
  members,
  onChanged,
}: {
  session: OrganisationAdministration;
  members: ReadonlyArray<DirectoryMember>;
  onChanged: () => Promise<void>;
}) {
  const [recoveries, setRecoveries] = useState<Array<RecoverySummary>>([]);
  const [target, setTarget] = useState("");
  const [recoveryLink, setRecoveryLink] = useState<string | undefined>(
    undefined,
  );
  const action = useAction();
  const toast = useToast();
  const { run } = action;

  const refresh = useCallback(async () => {
    setRecoveries(await session.recovery().list());
  }, [session]);

  useEffect(() => {
    void run(refresh);
  }, [run, refresh]);

  const memberOf = (userId: string): DirectoryMember | undefined =>
    members.find((member) => member.userId === userId);
  const recoverable = members.filter(
    (member) =>
      member.status === "confirmed" &&
      member.role !== "owner" &&
      member.userId !== session.user.id,
  );

  return (
    <div className="stack">
      <div className="notice small">
        Recovery takes two admins: one requests it, and another approves it and
        hands the one-time link to the member directly. If the member signs in
        with their old password, the recovery is cancelled automatically.
      </div>
      <form
        className="row wrap"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            await session.recovery().request(target);
            setTarget("");
            await refresh();
          });
        }}
      >
        <select
          className="input"
          style={{ flex: "1 1 240px" }}
          aria-label="Member to recover"
          required
          value={target}
          onChange={(event) => {
            setTarget(event.target.value);
          }}
        >
          <option value="">Choose a member to recover…</option>
          {recoverable.map((member) => (
            <option key={member.userId} value={member.userId}>
              {member.name} ({member.email})
            </option>
          ))}
        </select>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy || target === ""}
        >
          Request recovery
        </button>
      </form>
      {recoveryLink === undefined ? null : (
        <div className="notice stack">
          <p className="small">
            This one-time recovery link is valid for 3 days. Give it directly to
            the member themselves.
          </p>
          <code style={{ wordBreak: "break-all" }}>{recoveryLink}</code>
          <button
            type="button"
            className="btn btn-small"
            onClick={() => {
              void copySecret(recoveryLink).then(() => {
                toast("Copied the recovery link.");
              });
            }}
          >
            Copy link
          </button>
        </div>
      )}
      <ErrorText message={action.error} />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th>Member</th>
              <th>Status</th>
              <th>Requested</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {recoveries.map((recovery) => {
              const member = memberOf(recovery.userId);
              const canApprove =
                recovery.status === "pending" &&
                recovery.requestedBy !== session.user.id;
              const canComplete =
                recovery.status === "rekeyed" &&
                member?.certificate !== undefined;
              const open =
                recovery.status === "pending" ||
                recovery.status === "approved" ||
                recovery.status === "rekeyed";

              return (
                <tr key={recovery.id}>
                  <td>{recovery.email}</td>
                  <td>
                    <RecoveryStatusBadge recovery={recovery} member={member} />
                  </td>
                  <td className="small muted">
                    {memberOf(recovery.requestedBy)?.email ??
                      recovery.requestedBy}
                    <br />
                    {new Date(recovery.createdAt).toLocaleString(undefined)}
                  </td>
                  <td>
                    <div className="row wrap">
                      {canApprove ? (
                        <button
                          type="button"
                          className="btn btn-primary btn-small"
                          disabled={action.busy}
                          onClick={() => {
                            void action.run(async () => {
                              const { recoveryToken } = await session
                                .recovery()
                                .approve(recovery.id);

                              setRecoveryLink(
                                `${location.origin}/#/recover?${new URLSearchParams({ token: recoveryToken }).toString()}`,
                              );
                              await refresh();
                              await onChanged();
                            });
                          }}
                        >
                          Approve
                        </button>
                      ) : null}
                      {canComplete ? (
                        <button
                          type="button"
                          className="btn btn-primary btn-small"
                          disabled={action.busy}
                          onClick={() => {
                            void action.run(async () => {
                              const restored = await session
                                .recovery()
                                .complete(recovery.id);

                              toast(
                                `Recovery complete: restored ${String(restored.vaults)} vaults and ${String(restored.groups)} groups.`,
                              );
                              await refresh();
                            });
                          }}
                        >
                          Complete
                        </button>
                      ) : null}
                      {open ? (
                        <button
                          type="button"
                          className="btn btn-ghost btn-small"
                          disabled={action.busy}
                          onClick={() => {
                            void action.run(async () => {
                              await session.recovery().cancel(recovery.id);
                              await refresh();
                              await onChanged();
                            });
                          }}
                        >
                          Cancel
                        </button>
                      ) : null}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {recoveries.length === 0 ? (
          <p className="empty">No recoveries yet.</p>
        ) : null}
      </div>
    </div>
  );
}

/**
 * ### RecoveryStatusBadge
 *
 * Explains where a recovery stands and what has to happen next.
 *
 * @param props Recovery and the recovered member
 * @returns The badge with a next-step hint
 */
function RecoveryStatusBadge({
  recovery,
  member,
}: {
  recovery: RecoverySummary;
  member: DirectoryMember | undefined;
}) {
  const text: Record<RecoverySummary["status"], [string, string]> = {
    pending: ["Awaiting approval", "Another admin needs to approve it"],
    approved: [
      "Awaiting member",
      "The member needs to set a new password with the recovery link",
    ],
    rekeyed:
      member?.certificate === undefined
        ? [
            "Awaiting key verification",
            "Verify the new fingerprint on the Members tab",
          ]
        : ["Ready to complete", "Click Complete to restore their vaults"],
    completed: ["Completed", ""],
    cancelled: ["Cancelled", ""],
  };
  const [label, hint] = text[recovery.status];

  return (
    <div>
      <span className="badge">{label}</span>
      {hint === "" ? null : <div className="small muted">{hint}</div>}
    </div>
  );
}
