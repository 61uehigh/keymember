import type { AuditRepository } from "./AuditRepository.js";
import type { ChangeFeedRepository } from "./ChangeFeedRepository.js";
import type { GroupRepository } from "./GroupRepository.js";
import type { InviteRepository } from "./InviteRepository.js";
import type { ItemRepository } from "./ItemRepository.js";
import type { LoginChallengeRepository } from "./LoginChallengeRepository.js";
import type { MembershipRepository } from "./MembershipRepository.js";
import type { OrganizationRepository } from "./OrganizationRepository.js";
import type { RecoveryRepository } from "./RecoveryRepository.js";
import type { SessionRepository } from "./SessionRepository.js";
import type { ShareRepository } from "./ShareRepository.js";
import type { SsoRepository } from "./SsoRepository.js";
import type { UserRepository } from "./UserRepository.js";
import type { VaultRepository } from "./VaultRepository.js";

/**
 * ### Repositories
 *
 * Every store a route reads or writes, bound to one connection or transaction. Routes and
 * services depend on these interfaces only; which database is behind them is decided where
 * the app is built (see `Store`).
 */
export interface Repositories {
  readonly audit: AuditRepository;
  readonly changeFeed: ChangeFeedRepository;
  readonly groups: GroupRepository;
  readonly invites: InviteRepository;
  readonly items: ItemRepository;
  readonly loginChallenges: LoginChallengeRepository;
  readonly memberships: MembershipRepository;
  readonly organizations: OrganizationRepository;
  readonly recoveries: RecoveryRepository;
  readonly sessions: SessionRepository;
  readonly shares: ShareRepository;
  readonly sso: SsoRepository;
  readonly users: UserRepository;
  readonly vaults: VaultRepository;
}
