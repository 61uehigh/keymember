import type { ItemOverview } from "@keymember/core";
import type { VaultPermission } from "@keymember/client";

export const PERMISSION_LABELS: Readonly<Record<VaultPermission, string>> = {
  view: "View",
  edit: "Edit",
  manage: "Manage",
};

/**
 * ### canEdit
 *
 * Whether a permission allows changing items.
 *
 * @param permission Access level
 * @returns Whether edits are allowed
 */
export function canEdit(permission: VaultPermission): boolean {
  return permission !== "view";
}

/**
 * ### typeLabel
 *
 * Korean label of an item type.
 *
 * @param type Item type
 * @returns Display label
 */
export function typeLabel(type: ItemOverview["type"]): string {
  return {
    login: "Login",
    "secure-note": "Secure note",
    "api-credential": "API credential",
    "ssh-key": "SSH key",
  }[type];
}
