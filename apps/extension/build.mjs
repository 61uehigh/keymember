import { cp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { build } from "esbuild";

const root = dirname(fileURLToPath(import.meta.url));

/**
 * Firefox runs the background as an event page (a classic script with a DOM) rather than a
 * service worker, has no offscreen documents, and needs an add-on id. Everything else is shared.
 *
 * @param {Record<string, unknown>} manifest Chrome manifest
 * @returns {Record<string, unknown>} Firefox manifest
 */
function firefoxManifest(manifest) {
  const {
    minimum_chrome_version: _chromeOnly,
    background: _serviceWorker,
    ...rest
  } = manifest;

  return {
    ...rest,
    background: { scripts: ["background.js"] },
    permissions: manifest.permissions.filter(
      (permission) => permission !== "offscreen",
    ),
    web_accessible_resources: manifest.web_accessible_resources.map(
      ({ use_dynamic_url: _dynamic, ...resource }) => resource,
    ),
    browser_specific_settings: {
      // Page-world content scripts need 128, the data collection declaration 140 (142 on Android)
      gecko: {
        id: "keymember@61uehigh.github.io",
        strict_min_version: "142.0",
        // The account email and (end-to-end encrypted) login data go to the organisation's own server
        data_collection_permissions: {
          required: ["authenticationInfo", "personallyIdentifyingInfo"],
        },
      },
    },
  };
}

/**
 * Builds the extension for one browser.
 *
 * @param {"chrome" | "firefox"} browser Target browser
 */
async function buildFor(browser) {
  const outdir = join(root, browser === "chrome" ? "dist" : "dist-firefox");
  const common = {
    bundle: true,
    minify: true,
    sourcemap: false,
    target: browser === "chrome" ? "chrome120" : "firefox142",
    legalComments: "none",
    define: {
      "process.env.NODE_ENV": '"production"',
      // Lets the minifier drop code paths the other browser does not have (offscreen documents)
      "process.env.KEYMEMBER_BROWSER": JSON.stringify(browser),
    },
    logLevel: "warning",
  };
  const page = (entry, out, jsx = false) =>
    build({
      ...common,
      entryPoints: [join(root, entry)],
      outfile: join(outdir, out),
      format: "iife",
      ...(jsx ? { jsx: "automatic" } : {}),
    });

  await rm(outdir, { recursive: true, force: true });
  await mkdir(outdir, { recursive: true });

  await Promise.all([
    // Chrome's service worker is an ES module; Firefox's event page and everything else are classic scripts
    build({
      ...common,
      entryPoints: [join(root, "src/background/index.ts")],
      outfile: join(outdir, "background.js"),
      format: browser === "chrome" ? "esm" : "iife",
    }),
    page("src/content/index.ts", "content.js"),
    ...(browser === "chrome"
      ? [page("src/offscreen/offscreen.ts", "offscreen.js")]
      : []),
    page("src/menu/menu.ts", "menu.js"),
    page("src/passkey/page.ts", "passkey-page.js"),
    page("src/passkey/bridge.ts", "passkey-bridge.js"),
    page("src/passkey/window.tsx", "passkey-window.js", true),
    page("src/popup/main.tsx", "popup.js", true),
  ]);

  await cp(join(root, "static"), outdir, { recursive: true });

  if (browser === "firefox") {
    const manifestPath = join(outdir, "manifest.json");
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));

    await writeFile(
      manifestPath,
      `${JSON.stringify(firefoxManifest(manifest), null, 2)}\n`,
    );
    await rm(join(outdir, "offscreen.html"));
  }

  console.log(`Built the ${browser} extension into ${outdir}`);
}

await buildFor("chrome");
await buildFor("firefox");
