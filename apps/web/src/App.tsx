import { parseInviteParams } from "@keymember/client";
import { useEffect, useState } from "react";
import { z } from "zod";

import { describeError } from "./lib/api.js";
import { AppStateProvider, useAppState } from "./lib/AppState.js";
import { navigate, useRoute } from "./lib/router.js";
import { AccountScreen } from "./screens/AccountScreen.js";
import { AdminScreen } from "./screens/AdminScreen.js";
import { BootstrapScreen } from "./screens/auth/BootstrapScreen.js";
import { JoinScreen } from "./screens/auth/JoinScreen.js";
import { LoginScreen } from "./screens/auth/LoginScreen.js";
import { RecoverScreen } from "./screens/auth/RecoverScreen.js";
import { ImportScreen } from "./screens/ImportScreen.js";
import { SharedItemScreen } from "./screens/ShareScreens.js";
import { VaultScreen } from "./screens/VaultScreen.js";
import { ToastProvider } from "./ui/primitives.js";

/**
 * ### App
 *
 * Root component: providers plus the router.
 *
 * @returns The application
 */
export function App() {
  return (
    <AppStateProvider>
      <ToastProvider>
        <Router />
      </ToastProvider>
    </AppStateProvider>
  );
}

/**
 * ### Router
 *
 * Picks the screen for the current hash route and lock state. Signed-out routes (join,
 * recover) work without a session; everything else needs one.
 *
 * @returns The current screen
 */
function Router() {
  const route = useRoute();
  const { session } = useAppState();
  const [status, setStatus] = useState<
    { bootstrapped: boolean } | { error: string } | undefined
  >(undefined);

  const signedIn = session !== undefined;

  // Asked again on every lock: the answer changes once this very page bootstraps the server
  useEffect(() => {
    if (signedIn) {
      return;
    }

    void fetch("/api/status")
      .then(async (response) =>
        z.object({ bootstrapped: z.boolean() }).parse(await response.json()),
      )
      .then(setStatus, (error: unknown) => {
        setStatus({ error: describeError(error) });
      });
  }, [signedIn]);

  // Share links open for anyone, signed in or not
  if (route.path.startsWith("/share/")) {
    return (
      <SharedItemScreen path={route.path} query={route.params.toString()} />
    );
  }

  if (route.path === "/join") {
    return (
      <JoinScreen
        initialToken={route.params.get("invite") ?? ""}
        initialEmail={route.params.get("email") ?? ""}
        link={parseInviteParams(route.params)}
      />
    );
  }

  if (route.path === "/recover" && session === undefined) {
    return <RecoverScreen initialToken={route.params.get("token") ?? ""} />;
  }

  // A session can only exist on a bootstrapped server, even if the status was fetched before bootstrap
  if (session !== undefined) {
    return <Shell path={route.path} />;
  }

  if (status === undefined) {
    return <p className="empty">Loading…</p>;
  }

  if ("error" in status) {
    return (
      <p className="empty error">Can't connect to the server: {status.error}</p>
    );
  }

  if (!status.bootstrapped) {
    return <BootstrapScreen />;
  }

  return <LoginScreen />;
}

const NAV: ReadonlyArray<{ path: string; label: string; adminOnly: boolean }> =
  [
    { path: "/vault", label: "Vault", adminOnly: false },
    { path: "/import", label: "Import", adminOnly: false },
    { path: "/admin", label: "Admin", adminOnly: true },
    { path: "/account", label: "Account", adminOnly: false },
  ];

/**
 * ### Shell
 *
 * Signed-in layout: top bar with navigation and lock, and the active screen.
 *
 * @param props Current route path
 * @returns The shell
 */
function Shell({ path }: { path: string }) {
  const { session, lock } = useAppState();
  const isAdmin = session?.user.role !== "member";
  const active = NAV.some(
    (entry) => entry.path === path && (!entry.adminOnly || isAdmin),
  )
    ? path
    : "/vault";

  return (
    <div className="shell">
      <header className="topbar">
        <span className="brand">
          🔑 <span className="brand-text">keymember</span>
        </span>
        <nav aria-label="Main menu">
          {NAV.filter((entry) => !entry.adminOnly || isAdmin).map((entry) => (
            <a
              key={entry.path}
              href={`#${entry.path}`}
              aria-current={active === entry.path ? "page" : undefined}
            >
              {entry.label}
            </a>
          ))}
        </nav>
        <button
          type="button"
          className="btn btn-small"
          onClick={() => {
            lock();
            navigate("/");
          }}
        >
          Lock
        </button>
      </header>
      {active === "/vault" ? (
        <main style={{ minHeight: 0 }}>
          <VaultScreen />
        </main>
      ) : (
        <main className="page">
          {active === "/import" ? <ImportScreen /> : null}
          {active === "/admin" ? <AdminScreen /> : null}
          {active === "/account" ? <AccountScreen /> : null}
        </main>
      )}
    </div>
  );
}
