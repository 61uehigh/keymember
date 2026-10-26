import type {
  DirectoryMember,
  GroupView,
  ItemSummary,
  Session,
  VaultPermission,
} from "@keymember/client";

const PERMISSIONS: ReadonlySet<string> = new Set(["view", "edit", "manage"]);

/**
 * ### isPermission
 *
 * Whether text typed on the command line names a vault permission.
 *
 * @param text Text to check
 * @returns Whether it is `view`, `edit` or `manage`
 */
export function isPermission(text: string): text is VaultPermission {
  return PERMISSIONS.has(text);
}

/**
 * ### findMember
 *
 * Finds a member by email.
 *
 * @param directory Member directory
 * @param email Member's email, in any case
 * @returns The member's directory entry
 */
export function findMember(
  directory: ReadonlyArray<DirectoryMember>,
  email: string,
): DirectoryMember {
  const member = directory.find(
    (candidate) => candidate.email === email.toLowerCase(),
  );

  if (member === undefined) {
    throw new Error(`No member with email ${email}`);
  }

  return member;
}

/**
 * ### memberIds
 *
 * Resolves member emails to user ids.
 *
 * @param session Logged-in session
 * @param emails Member emails
 * @returns User ids in the same order
 */
export async function memberIds(
  session: Session,
  emails: ReadonlyArray<string>,
): Promise<Array<string>> {
  const directory = await session.directory();

  return emails.map((email) => findMember(directory, email).userId);
}

/**
 * ### pickByRef
 *
 * Picks the one entry a command-line reference names, by the same rule for vaults, items and
 * groups: an exact id wins; otherwise a name that matches exactly; otherwise a name that
 * matches ignoring case. Two entries matching at the same step is an error naming their ids,
 * so the user can pass the id instead.
 *
 * @param entries Candidates
 * @param ref Id or name as typed
 * @param kind What the entries are, for messages
 * @param nameOf Name of an entry
 * @returns The entry
 */
export function pickByRef<T extends { readonly id: string }>(
  entries: ReadonlyArray<T>,
  ref: string,
  kind: string,
  nameOf: (entry: T) => string,
): T {
  const byId = entries.find((entry) => entry.id === ref);

  if (byId !== undefined) {
    return byId;
  }

  const lower = ref.toLowerCase();
  const steps = [
    entries.filter((entry) => nameOf(entry) === ref),
    entries.filter((entry) => nameOf(entry).toLowerCase() === lower),
  ];

  for (const matches of steps) {
    const [only, ...others] = matches;

    if (only !== undefined && others.length === 0) {
      return only;
    }

    if (only !== undefined) {
      throw new Error(
        `"${ref}" matches several ${kind}s (${matches.map((entry) => entry.id).join(", ")}); use the id`,
      );
    }
  }

  throw new Error(`No ${kind} "${ref}"`);
}

/**
 * ### resolveGroup
 *
 * Finds a verified group by id or name ({@link pickByRef}).
 *
 * @param session Logged-in session
 * @param ref Group name or id
 * @returns The group
 */
export async function resolveGroup(
  session: Session,
  ref: string,
): Promise<GroupView> {
  const group = pickByRef(
    await session.groups(),
    ref,
    "group",
    (entry) => entry.name,
  );

  if (group.certificate === undefined) {
    throw new Error(
      `Group ${ref} has no certificate from a trusted admin; refusing to use it`,
    );
  }

  return group;
}

/**
 * ### resolveVault
 *
 * Finds a vault by id or name ({@link pickByRef}).
 *
 * @param session Synced session
 * @param ref Vault name or id
 * @returns The vault id
 */
export function resolveVault(session: Session, ref: string): string {
  return pickByRef(session.listVaults(), ref, "vault", (vault) => vault.name)
    .id;
}

/**
 * ### resolveItem
 *
 * Finds an item by id or title ({@link pickByRef}).
 *
 * @param session Synced session
 * @param ref Item title or id
 * @returns The item summary
 */
export function resolveItem(session: Session, ref: string): ItemSummary {
  return pickByRef(
    session.listItems(),
    ref,
    "item",
    (item) => item.overview.title,
  );
}
