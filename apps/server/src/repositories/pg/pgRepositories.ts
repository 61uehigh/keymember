import type { Queryable } from "../../db/Database.js";
import type { Repositories } from "../Repositories.js";
import { PgAuditRepository } from "./PgAuditRepository.js";
import { PgChangeFeedRepository } from "./PgChangeFeedRepository.js";
import { PgGroupRepository } from "./PgGroupRepository.js";
import { PgInviteRepository } from "./PgInviteRepository.js";
import { PgItemRepository } from "./PgItemRepository.js";
import { PgLoginChallengeRepository } from "./PgLoginChallengeRepository.js";
import { PgMembershipRepository } from "./PgMembershipRepository.js";
import { PgOrganizationRepository } from "./PgOrganizationRepository.js";
import { PgRecoveryRepository } from "./PgRecoveryRepository.js";
import { PgSessionRepository } from "./PgSessionRepository.js";
import { PgShareRepository } from "./PgShareRepository.js";
import { PgSsoRepository } from "./PgSsoRepository.js";
import { PgUserRepository } from "./PgUserRepository.js";
import { PgVaultRepository } from "./PgVaultRepository.js";

/**
 * ### pgRepositories
 *
 * The PostgreSQL repositories, for PGlite and for a real PostgreSQL server alike.
 *
 * @param db Connection or transaction to work in
 * @returns The repositories
 */
export function pgRepositories(db: Queryable): Repositories {
  return {
    audit: new PgAuditRepository(db),
    changeFeed: new PgChangeFeedRepository(db),
    groups: new PgGroupRepository(db),
    invites: new PgInviteRepository(db),
    items: new PgItemRepository(db),
    loginChallenges: new PgLoginChallengeRepository(db),
    memberships: new PgMembershipRepository(db),
    organizations: new PgOrganizationRepository(db),
    recoveries: new PgRecoveryRepository(db),
    sessions: new PgSessionRepository(db),
    shares: new PgShareRepository(db),
    sso: new PgSsoRepository(db),
    users: new PgUserRepository(db),
    vaults: new PgVaultRepository(db),
  };
}
