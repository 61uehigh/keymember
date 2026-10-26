import type {
  DirectoryMember,
  GroupView,
  OrganisationAdministration,
} from "@keymember/client";
import { useCallback, useEffect, useState } from "react";

import { ErrorText, Field, useAction, useToast } from "../../ui/primitives.js";

/**
 * ### GroupsTab
 *
 * Creates groups and changes their members. Removing a member rotates the group key; the
 * vaults the group carries keep their keys until a manager rotates them.
 *
 * @param props Session and member directory
 * @returns The tab content
 */
export function GroupsTab({
  session,
  members,
}: {
  session: OrganisationAdministration;
  members: ReadonlyArray<DirectoryMember>;
}) {
  const [groups, setGroups] = useState<Array<GroupView>>([]);
  const [name, setName] = useState("");
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [adding, setAdding] = useState<Readonly<Record<string, string>>>({});
  const load = useAction();
  const action = useAction();
  const toast = useToast();
  const { run } = load;
  const admin = session.groupAdmin();

  const refresh = useCallback(async () => {
    setGroups(await session.groups());
  }, [session]);

  useEffect(() => {
    void run(refresh);
  }, [run, refresh]);

  const certified = members.filter(
    (member) =>
      member.certificate !== undefined && member.status === "confirmed",
  );
  const emailOf = (userId: string): string =>
    members.find((member) => member.userId === userId)?.email ?? userId;

  return (
    <div className="stack">
      <form
        className="card stack"
        onSubmit={(event) => {
          event.preventDefault();
          void action.run(async () => {
            await admin.create(name.trim(), [...selected]);
            toast(`Created group "${name.trim()}".`);
            setName("");
            setSelected(new Set());
            await refresh();
          });
        }}
      >
        <h2>New group</h2>
        <Field
          label="Name"
          required
          maxLength={200}
          placeholder="e.g. Engineering"
          value={name}
          onChange={(event) => {
            setName(event.target.value);
          }}
        />
        <fieldset
          className="stack"
          style={{ border: 0, padding: 0, margin: 0 }}
        >
          <legend className="small muted">
            Members (verified members only)
          </legend>
          <div className="row wrap">
            {certified.map((member) => (
              <label key={member.userId} className="row small">
                <input
                  type="checkbox"
                  checked={selected.has(member.userId)}
                  onChange={(event) => {
                    const next = new Set(selected);

                    if (event.target.checked) {
                      next.add(member.userId);
                    } else {
                      next.delete(member.userId);
                    }

                    setSelected(next);
                  }}
                />
                {member.email}
              </label>
            ))}
          </div>
        </fieldset>
        <div>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={action.busy || name.trim() === ""}
          >
            Create group
          </button>
        </div>
      </form>
      <ErrorText message={load.error ?? action.error} />
      {groups.length === 0 ? <p className="muted">No groups yet.</p> : null}
      {groups.map((group) => {
        const outside = certified.filter(
          (member) => !group.memberIds.includes(member.userId),
        );
        const pick = adding[group.id] ?? "";

        return (
          <section key={group.id} className="card stack">
            <div className="row spread">
              <h2>
                {group.name}{" "}
                {group.certificate === undefined ? (
                  <span className="badge badge-warn">Signature mismatch</span>
                ) : (
                  <span className="badge badge-ok">
                    Key v{String(group.keysetVersion)}
                  </span>
                )}
              </h2>
              <button
                type="button"
                className="btn btn-danger btn-small"
                disabled={action.busy}
                onClick={() => {
                  if (
                    window.confirm(
                      `Delete the group "${group.name}"? All vault access granted through this group will be removed.`,
                    )
                  ) {
                    void action.run(async () => {
                      await admin.delete(group.id);
                      await refresh();
                    });
                  }
                }}
              >
                Delete
              </button>
            </div>
            <ul
              className="stack"
              style={{ margin: 0, padding: 0, listStyle: "none" }}
            >
              {group.memberIds.map((userId) => (
                <li key={userId} className="row spread">
                  <span>{emailOf(userId)}</span>
                  <button
                    type="button"
                    className="btn btn-small"
                    disabled={action.busy || group.certificate === undefined}
                    onClick={() => {
                      if (
                        window.confirm(
                          `Remove ${emailOf(userId)} from the group and rotate the group key? For passwords they have already seen, you still need to rotate those vault keys and change the passwords separately.`,
                        )
                      ) {
                        void action.run(async () => {
                          await admin.removeMember(group.id, userId);
                          toast("Rotated the group key.");
                          await refresh();
                        });
                      }
                    }}
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
            {outside.length === 0 || group.certificate === undefined ? null : (
              <form
                className="row wrap"
                onSubmit={(event) => {
                  event.preventDefault();
                  void action.run(async () => {
                    await admin.addMember(group.id, pick);
                    setAdding({ ...adding, [group.id]: "" });
                    await refresh();
                  });
                }}
              >
                <select
                  className="input"
                  style={{ flex: "1 1 200px" }}
                  aria-label={`Member to add to ${group.name}`}
                  value={pick}
                  onChange={(event) => {
                    setAdding({ ...adding, [group.id]: event.target.value });
                  }}
                >
                  <option value="">Choose a member…</option>
                  {outside.map((member) => (
                    <option key={member.userId} value={member.userId}>
                      {member.email}
                    </option>
                  ))}
                </select>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={action.busy || pick === ""}
                >
                  Add
                </button>
              </form>
            )}
          </section>
        );
      })}
    </div>
  );
}
