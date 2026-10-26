import { inviteLinkUrl } from "@keymember/client";
import type {
  DirectoryMember,
  OffboardingReport,
  OrganisationAdministration,
} from "@keymember/client";
import { useState } from "react";

import { copySecret } from "../../lib/clipboard.js";
import {
  Dialog,
  ErrorText,
  Field,
  useAction,
  useToast,
} from "../../ui/primitives.js";

const STATUS_LABELS: Readonly<Record<DirectoryMember["status"], string>> = {
  accepted: "Awaiting verification",
  confirmed: "Active",
  suspended: "Suspended",
  recovering: "Recovering",
};

/**
 * ### MembersTab
 *
 * Member directory with invite, certify and suspend actions.
 *
 * @param props Session, directory and refresh callback
 * @returns The tab content
 */
export function MembersTab({
  session,
  members,
  onChanged,
}: {
  session: OrganisationAdministration;
  members: ReadonlyArray<DirectoryMember>;
  onChanged: () => Promise<void>;
}) {
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState<"member" | "admin">("member");
  const [sent, setSent] = useState<{ email: string; url: string } | undefined>(
    undefined,
  );
  const [certifying, setCertifying] = useState<DirectoryMember | undefined>(
    undefined,
  );
  const [offboarded, setOffboarded] = useState<
    { email: string; report: OffboardingReport } | undefined
  >(undefined);
  const action = useAction();
  const toast = useToast();

  return (
    <div className="stack">
      <form
        className="card stack"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            const email = inviteEmail.trim().toLowerCase();
            const { link } = await session.orgAdmin().invite(email, inviteRole);

            setSent({ email, url: inviteLinkUrl(location.origin, link) });
            setInviteEmail("");
          });
        }}
      >
        <h2>Invite</h2>
        <div className="row wrap">
          <input
            className="input"
            style={{ flex: "1 1 240px" }}
            type="email"
            required
            placeholder="name@example.com"
            aria-label="Email to invite"
            value={inviteEmail}
            onChange={(event) => {
              setInviteEmail(event.target.value);
            }}
          />
          <select
            className="input"
            style={{ flex: "0 0 120px" }}
            aria-label="Role"
            value={inviteRole}
            onChange={(event) => {
              setInviteRole(
                event.target.value === "admin" ? "admin" : "member",
              );
            }}
          >
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={action.busy}
          >
            Create invite
          </button>
        </div>
        {sent === undefined ? null : (
          <InviteSender
            email={sent.email}
            url={sent.url}
            onCopied={(what) => {
              toast(what);
            }}
          />
        )}
      </form>
      <ErrorText message={action.error} />
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr>
              <th>Member</th>
              <th>Role</th>
              <th>Status</th>
              <th>Key</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {members.map((member) => (
              <tr key={member.userId}>
                <td>
                  <div>{member.name}</div>
                  <div className="small muted">{member.email}</div>
                </td>
                <td>
                  {member.role === "owner"
                    ? "Owner"
                    : member.role === "admin"
                      ? "Admin"
                      : "Member"}
                </td>
                <td>{STATUS_LABELS[member.status]}</td>
                <td>
                  {member.certificate === undefined ? (
                    <span className="badge badge-warn">Unverified</span>
                  ) : (
                    <span className="badge badge-ok">Verified</span>
                  )}
                  {/* Only verified keys show a fingerprint; showing an unverified one invites copying it into the certify dialog */}
                  {member.certificate === undefined ? null : (
                    <div className="small muted mono">{member.fingerprint}</div>
                  )}
                </td>
                <td>
                  <div className="row">
                    {member.status === "accepted" ? (
                      <button
                        type="button"
                        className="btn btn-primary btn-small"
                        onClick={() => {
                          setCertifying(member);
                        }}
                      >
                        Verify
                      </button>
                    ) : null}
                    {member.status === "confirmed" &&
                    member.role !== "owner" &&
                    member.userId !== session.user.id ? (
                      <button
                        type="button"
                        className="btn btn-danger btn-small"
                        disabled={action.busy}
                        onClick={() => {
                          if (
                            window.confirm(
                              `Offboard ${member.email}? This signs out all of their sessions, removes their vault and group access, and immediately rotates the keys of the groups they could open and of the vaults you manage.`,
                            )
                          ) {
                            void action.run(async () => {
                              const report = await session
                                .orgAdmin()
                                .offboard(member.userId);

                              setOffboarded({ email: member.email, report });
                              await onChanged();
                            });
                          }
                        }}
                      >
                        Offboard
                      </button>
                    ) : null}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {offboarded === undefined ? null : (
        <Dialog
          title={`Offboarded ${offboarded.email}`}
          onClose={() => {
            setOffboarded(undefined);
          }}
        >
          <ul className="stack">
            <li>
              Group keys rotated:{" "}
              {String(offboarded.report.groupsRotated.length)}
            </li>
            <li>
              Vault keys rotated:{" "}
              {String(offboarded.report.vaultsRotated.length)}
            </li>
          </ul>
          {offboarded.report.vaultsPending.length === 0 ? (
            <p>Nothing left to do.</p>
          ) : (
            <div className="stack">
              <p>
                {String(offboarded.report.vaultsPending.length)} vaults you
                don&rsquo;t manage still need a new key. Ask each vault&rsquo;s
                managers to rotate it. They also see &ldquo;Key rotation
                needed&rdquo; on those vaults.
              </p>
              <ul className="stack">
                {offboarded.report.vaultsPending.map((pending) => (
                  <li key={pending.vaultId} className="small">
                    {pending.managerIds.length === 0
                      ? "Vault with no other manager: no one can rotate its key"
                      : `Managers: ${pending.managerIds
                          .map(
                            (userId) =>
                              members.find(
                                (candidate) => candidate.userId === userId,
                              )?.email ?? userId,
                          )
                          .join(", ")}`}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <p className="hint">
            Rotating keys can't take back passwords they have already seen. Also
            change the passwords of the accounts the departing member used.
          </p>
          <div className="dialog-actions">
            <button
              type="button"
              className="btn btn-primary"
              onClick={() => {
                setOffboarded(undefined);
              }}
            >
              Close
            </button>
          </div>
        </Dialog>
      )}
      {certifying === undefined ? null : (
        <CertifyDialog
          member={certifying}
          onClose={() => {
            setCertifying(undefined);
          }}
          onCertify={async (fingerprint) => {
            await session.orgAdmin().certify(certifying.userId, fingerprint);
            setCertifying(undefined);
            toast(`Verified ${certifying.email}.`);
            await onChanged();
          }}
        />
      )}
    </div>
  );
}

/**
 * ### CertifyDialog
 *
 * Asks the admin to type the fingerprint the member read out to them. Typing it, rather than
 * clicking "matches", forces an actual comparison.
 *
 * @param props Member to certify and callbacks
 * @returns The dialog
 */
function CertifyDialog({
  member,
  onClose,
  onCertify,
}: {
  member: DirectoryMember;
  onClose: () => void;
  onCertify: (fingerprint: string) => Promise<void>;
}) {
  const [fingerprint, setFingerprint] = useState("");
  const action = useAction();

  return (
    <Dialog title={`Verify ${member.name}`} onClose={onClose}>
      <p>
        Ask {member.email} directly (in person, by phone, or by Slack DM) to
        read out the fingerprint shown on their own screen, and enter it here.
        If it doesn&rsquo;t match the value the server shows, verification
        fails.
      </p>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(() => onCertify(fingerprint.trim().toLowerCase()));
        }}
      >
        <Field
          label="Fingerprint from the member"
          required
          autoFocus
          placeholder="0000-0000-0000-0000-0000"
          className="input mono"
          value={fingerprint}
          onChange={(event) => {
            setFingerprint(event.target.value);
          }}
          autoComplete="off"
          spellCheck={false}
        />
        <ErrorText message={action.error} />
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={action.busy}
          >
            Verify
          </button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * ### inviteMessage
 *
 * The invitation text for email or chat.
 *
 * @param url Invite link
 * @returns The message body
 */
function inviteMessage(url: string): string {
  return [
    "You're invited to keymember, our team password manager.",
    "",
    "Open the link below to join. It works once and expires in 7 days.",
    url,
    "",
    "Don't forward this link to anyone else.",
  ].join("\n");
}

/**
 * ### InviteSender
 *
 * Hands a new invite link to the admin's own mail app or chat, never to keymember's server: the
 * link carries the secret that lets the admin's app certify the member without a fingerprint
 * check, so it must reach the member over a channel the server does not control.
 *
 * @param props Invitee, link, and a callback to confirm copies
 * @returns The sending options
 */
function InviteSender({
  email,
  url,
  onCopied,
}: {
  email: string;
  url: string;
  onCopied: (message: string) => void;
}) {
  const mailto = `mailto:${encodeURIComponent(email)}?${new URLSearchParams({
    subject: "keymember invite",
    body: inviteMessage(url),
  })
    .toString()
    .replaceAll("+", "%20")}`;

  return (
    <div className="notice stack">
      <p className="small">
        This is the invite link for {email}. Send it only to them, by email or
        Slack: anyone who has the link can sign up as this email. Once they
        join, they are verified automatically if this Admin screen is open.
      </p>
      <code style={{ wordBreak: "break-all" }}>{url}</code>
      <div className="row wrap">
        <a className="btn btn-small btn-primary" href={mailto}>
          Send by email
        </a>
        <button
          type="button"
          className="btn btn-small"
          onClick={() => {
            void copySecret(inviteMessage(url)).then(() => {
              onCopied(
                `Copied the invite message. Paste it into a Slack DM with ${email} and send it.`,
              );
              // Opens the Slack app when installed; otherwise nothing happens and the copy remains
              window.location.href = "slack://open";
            });
          }}
        >
          Send via Slack
        </button>
        <button
          type="button"
          className="btn btn-small"
          onClick={() => {
            void copySecret(url).then(() => {
              onCopied("Copied the invite link.");
            });
          }}
        >
          Copy link
        </button>
      </div>
    </div>
  );
}
