import type { CommandDeps } from "./CommandDeps.js";
import { memberIds, resolveGroup } from "../lookups.js";

/**
 * ### GroupCommands
 *
 * Commands that list groups and, for admins, create, change and delete them.
 */
export class GroupCommands {
  readonly #deps: CommandDeps;

  /**
   * ### constructor
   *
   * @param deps Terminal and session access
   */
  constructor(deps: CommandDeps) {
    this.#deps = deps;
  }

  /**
   * ### list
   *
   * Lists groups with their members. Groups whose certificate does not verify are marked.
   */
  async list(): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const directory = await session.directory();
      const emails = new Map(
        directory.map((member) => [member.userId, member.email]),
      );

      for (const group of await session.groups()) {
        const members = group.memberIds
          .map((userId) => emails.get(userId) ?? userId)
          .join(",");
        const state = group.certificate === undefined ? "UNVERIFIED" : "ok";

        this.#deps.io.print(
          `${group.id}\tv${String(group.keysetVersion)}\t${state}\t${group.name}\t${members}`,
        );
      }
    });
  }

  /**
   * ### create
   *
   * Creates a group.
   *
   * @param name Group name
   * @param emails Initial members
   */
  async create(name: string, emails: ReadonlyArray<string>): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const userIds = await memberIds(session, emails);
      const groupId = await session.groupAdmin().create(name, userIds);

      this.#deps.io.print(groupId);
    });
  }

  /**
   * ### add
   *
   * Adds a member to a group.
   *
   * @param groupRef Group name or id
   * @param email Member to add
   */
  async add(groupRef: string, email: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const group = await resolveGroup(session, groupRef);
      const [userId = ""] = await memberIds(session, [email]);

      await session.groupAdmin().addMember(group.id, userId);
      this.#deps.io.print(`Added ${email} to ${group.name}`);
    });
  }

  /**
   * ### remove
   *
   * Removes a member from a group by rotating the group key.
   *
   * @param groupRef Group name or id
   * @param email Member to remove
   */
  async remove(groupRef: string, email: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const group = await resolveGroup(session, groupRef);
      const [userId = ""] = await memberIds(session, [email]);

      await session.groupAdmin().removeMember(group.id, userId);
      this.#deps.io.print(
        `Removed ${email} from ${group.name}; rotate the group's vaults to cut off what they already saw`,
      );
    });
  }

  /**
   * ### delete
   *
   * Deletes a group and the vault access it carried.
   *
   * @param groupRef Group name or id
   */
  async delete(groupRef: string): Promise<void> {
    await this.#deps.sessions.withSession(async (session) => {
      const group = await resolveGroup(session, groupRef);

      await session.groupAdmin().delete(group.id);
      this.#deps.io.print(`Deleted group ${group.name}`);
    });
  }
}
