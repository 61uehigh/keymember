import type { ReactNode } from "react";

/**
 * ### Shell
 *
 * Header and body frame shared by every screen.
 *
 * @param props Optional header action and content
 * @returns The framed screen
 */
export function Shell({
  action,
  children,
}: {
  action?: ReactNode;
  children: ReactNode;
}) {
  return (
    <>
      <header>
        <span className="brand">🔑 keymember</span>
        {action}
      </header>
      <div className="body">{children}</div>
    </>
  );
}
