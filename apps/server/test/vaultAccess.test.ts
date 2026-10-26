import { describe, expect, it } from "vitest";

import type { VaultRepository } from "../src/repositories/VaultRepository.js";
import { requireVaultPermission } from "../src/services/vaultAccess.js";

/**
 * ### vaultsWith
 *
 * A vault store that reports fixed permissions, standing in for the database.
 *
 * @param permissions Permissions the user holds on the vault, directly and through groups
 * @returns The stand-in
 */
function vaultsWith(
  permissions: ReadonlyArray<"view" | "edit" | "manage">,
): Pick<VaultRepository, "accessOf"> {
  return {
    accessOf: () =>
      Promise.resolve(
        permissions.map((permission) => ({
          permission,
          kind: "shared" as const,
          keyGeneration: 3,
        })),
      ),
  };
}

describe("requireVaultPermission", () => {
  it("uses the strongest of the user's direct and group permissions", async () => {
    await expect(
      requireVaultPermission(
        vaultsWith(["view", "manage"]),
        "v",
        "u",
        "manage",
      ),
    ).resolves.toEqual({ kind: "shared", keyGeneration: 3 });
  });

  it("answers 403 for too weak a permission and 404 for none, so ids cannot be probed", async () => {
    await expect(
      requireVaultPermission(vaultsWith(["view"]), "v", "u", "edit"),
    ).rejects.toMatchObject({ kind: "forbidden" });
    await expect(
      requireVaultPermission(vaultsWith([]), "v", "u", "view"),
    ).rejects.toMatchObject({ kind: "not_found" });
  });
});
