import { describeError } from "@keymember/client";
import type { DirectoryMember, InvitedCertification } from "@keymember/client";
import { useCallback, useEffect, useState } from "react";

import { useSession } from "../lib/AppState.js";
import { ErrorText, useAction } from "../ui/primitives.js";
import { MembersTab } from "./admin/MembersTab.js";
import { GroupsTab } from "./admin/GroupsTab.js";
import { RecoveryTab } from "./admin/RecoveryTab.js";
import { PoliciesTab } from "./admin/PoliciesTab.js";
import { AuditTab } from "./admin/AuditTab.js";

type Tab = "members" | "groups" | "recovery" | "policies" | "audit";

const TABS: ReadonlyArray<{ id: Tab; label: string }> = [
  { id: "members", label: "Members" },
  { id: "groups", label: "Groups" },
  { id: "recovery", label: "Account recovery" },
  { id: "policies", label: "Policies" },
  { id: "audit", label: "Audit log" },
];

/**
 * ### AdminScreen
 *
 * Admin console with tabs for members, groups, recovery, policies and the audit log.
 *
 * @returns The admin screen
 */
export function AdminScreen() {
  const session = useSession();
  const [tab, setTab] = useState<Tab>("members");
  const [members, setMembers] = useState<Array<DirectoryMember>>([]);
  const [certification, setCertification] = useState<
    InvitedCertification | undefined
  >(undefined);
  const load = useAction();
  const { run } = load;

  const refresh = useCallback(async () => {
    // Members who joined through this admin's links are certified as soon as the console opens.
    // The list loads either way: one member failing must not hide everyone else
    try {
      setCertification(await session.orgAdmin().certifyInvited());
    } catch (error) {
      setCertification({
        certified: [],
        needsFingerprint: [],
        failed: [{ email: "", reason: describeError(error) }],
      });
    }

    setMembers(await session.directory());
  }, [session]);

  useEffect(() => {
    void run(refresh);
  }, [run, refresh]);

  return (
    <div className="page-inner stack">
      <h1>Admin</h1>
      <div className="tabs" role="tablist">
        {TABS.map((entry) => (
          <button
            key={entry.id}
            type="button"
            role="tab"
            aria-selected={tab === entry.id}
            onClick={() => {
              setTab(entry.id);
            }}
          >
            {entry.label}
          </button>
        ))}
      </div>
      <ErrorText message={load.error} />
      {certification === undefined ? null : (
        <CertificationNotice result={certification} />
      )}
      {tab === "members" ? (
        <MembersTab session={session} members={members} onChanged={refresh} />
      ) : null}
      {tab === "groups" ? (
        <GroupsTab session={session} members={members} />
      ) : null}
      {tab === "recovery" ? (
        <RecoveryTab session={session} members={members} onChanged={refresh} />
      ) : null}
      {tab === "policies" ? <PoliciesTab session={session} /> : null}
      {tab === "audit" ? (
        <AuditTab session={session} members={members} />
      ) : null}
    </div>
  );
}

/**
 * ### CertificationNotice
 *
 * Tells the admin who joined by link but still needs a fingerprint comparison, and whose
 * automatic certification failed.
 *
 * @param props Outcome of the automatic certification
 * @returns The notice, or nothing when there is nothing to report
 */
function CertificationNotice({ result }: { result: InvitedCertification }) {
  if (result.needsFingerprint.length === 0 && result.failed.length === 0) {
    return null;
  }

  return (
    <div className="notice stack" role="status">
      {result.needsFingerprint.length === 0 ? null : (
        <p className="small">
          These members joined through a link that can't verify them on its own
          (an admin invite, an old link, or a re-registered account). Compare
          fingerprints to verify them: {result.needsFingerprint.join(", ")}
        </p>
      )}
      {result.failed.map((failure) => (
        <p key={failure.email} className="small error">
          {failure.email === "" ? "" : `${failure.email}: `}
          {failure.reason}
        </p>
      ))}
    </div>
  );
}
