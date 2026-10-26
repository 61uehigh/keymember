import type {
  DirectoryMember,
  GroupView,
  PrincipalType,
  VaultAccessControl,
  VaultPermission,
  VaultView,
} from "@keymember/client";
import { useEffect, useState } from "react";

import { Dialog, ErrorText, useAction, useToast } from "../../ui/primitives.js";
import { PERMISSION_LABELS } from "./permissions.js";

/**
 * ### ShareDialog
 *
 * Shows who can open a shared vault, adds certified members and groups, and removes them by
 * rotating the vault key so they cannot read anything written afterwards.
 *
 * @param props Session, vault and close handler
 * @returns The dialog
 */
export function ShareDialog({
  session,
  vault,
  onClose,
}: {
  session: VaultAccessControl;
  vault: VaultView;
  onClose: () => void;
}) {
  const [members, setMembers] = useState<Array<DirectoryMember>>([]);
  const [groups, setGroups] = useState<Array<GroupView>>([]);
  const [access, setAccess] = useState<
    Array<{
      principalType: PrincipalType;
      principalId: string;
      permission: VaultPermission;
    }>
  >([]);
  const [newMember, setNewMember] = useState("");
  const [newPermission, setNewPermission] = useState<VaultPermission>("view");
  const load = useAction();
  const action = useAction();
  const toast = useToast();
  const { run } = load;

  const refresh = async (): Promise<void> => {
    const [directory, groupList, entries] = await Promise.all([
      session.directory(),
      session.groups(),
      session.vaultAccess(vault.id),
    ]);

    setMembers(directory);
    setGroups(groupList);
    setAccess(entries);
  };

  useEffect(() => {
    void run(refresh);
    // refresh closes over stable props; re-running on its identity would refetch every render
  }, [run]); // eslint-disable-line react-hooks/exhaustive-deps

  const nameOf = (principalId: string): string =>
    members.find((member) => member.userId === principalId)?.email ??
    groups.find((group) => group.id === principalId)?.name ??
    principalId;
  const candidates = members.filter(
    (member) =>
      member.certificate !== undefined &&
      member.status === "confirmed" &&
      !access.some((entry) => entry.principalId === member.userId),
  );
  const groupCandidates = groups.filter(
    (group) =>
      group.certificate !== undefined &&
      !access.some((entry) => entry.principalId === group.id),
  );

  return (
    <Dialog title={`Share "${vault.name}"`} onClose={onClose}>
      <ErrorText message={load.error ?? action.error} />
      <ul
        className="stack"
        style={{ margin: 0, padding: 0, listStyle: "none" }}
      >
        {access.map((entry) => (
          <li key={entry.principalId} className="row spread">
            <span>
              {entry.principalType === "group" ? (
                <span className="badge">Group</span>
              ) : null}{" "}
              {nameOf(entry.principalId)}{" "}
              <span className="badge">
                {PERMISSION_LABELS[entry.permission]}
              </span>
            </span>
            {entry.principalId === session.user.id ? null : (
              <button
                type="button"
                className="btn btn-danger btn-small"
                disabled={action.busy}
                onClick={() => {
                  if (
                    window.confirm(
                      `Remove ${nameOf(entry.principalId)}${entry.principalType === "group" ? " (group)" : ""} and rotate the vault key? Passwords they have already seen still need to be changed separately.`,
                    )
                  ) {
                    void action.run(async () => {
                      await session.rotateVaultKey(vault.id, [
                        entry.principalId,
                      ]);
                      await refresh();
                      toast("Removed and rotated the key.");
                    });
                  }
                }}
              >
                Remove
              </button>
            )}
          </li>
        ))}
      </ul>
      <form
        className="row wrap"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            const [type, principalId = ""] = newMember.split(":");

            if (type === "group") {
              await session.grantGroupAccess(
                vault.id,
                principalId,
                newPermission,
              );
            } else {
              await session.grantAccess(vault.id, principalId, newPermission);
            }

            setNewMember("");
            await refresh();
          });
        }}
      >
        <select
          className="input"
          style={{ flex: "1 1 200px" }}
          aria-label="Member or group to share with"
          required
          value={newMember}
          onChange={(event) => {
            setNewMember(event.target.value);
          }}
        >
          <option value="">Choose a member or group…</option>
          {candidates.length === 0 ? null : (
            <optgroup label="Members">
              {candidates.map((member) => (
                <option key={member.userId} value={`user:${member.userId}`}>
                  {member.name} ({member.email})
                </option>
              ))}
            </optgroup>
          )}
          {groupCandidates.length === 0 ? null : (
            <optgroup label="Groups">
              {groupCandidates.map((group) => (
                <option key={group.id} value={`group:${group.id}`}>
                  {group.name} ({String(group.memberIds.length)})
                </option>
              ))}
            </optgroup>
          )}
        </select>
        <select
          className="input"
          style={{ flex: "0 0 110px" }}
          aria-label="Permission"
          value={newPermission}
          onChange={(event) => {
            setNewPermission(
              event.target.value === "manage"
                ? "manage"
                : event.target.value === "edit"
                  ? "edit"
                  : "view",
            );
          }}
        >
          <option value="view">View</option>
          <option value="edit">Edit</option>
          <option value="manage">Manage</option>
        </select>
        <button
          type="submit"
          className="btn btn-primary"
          disabled={action.busy || newMember === ""}
        >
          Add
        </button>
      </form>
      <p className="hint">
        Only members and groups whose keys an admin has verified are listed.
        When you share with a group, people who join it later can open the vault
        right away.
      </p>
      <div className="dialog-actions">
        <button
          type="button"
          className="btn"
          disabled={action.busy}
          onClick={() => {
            void action.run(async () => {
              await session.rotateVaultKey(vault.id);
              toast("Rotated the vault key.");
            });
          }}
        >
          Rotate key
        </button>
        <button type="button" className="btn btn-primary" onClick={onClose}>
          Close
        </button>
      </div>
    </Dialog>
  );
}
