// Renders the keymember icons into the files the apps ship. Run after changing an SVG here:
// node branding/render.mjs (needs Playwright's Chromium, installed for the E2E tests).
//   mark.svg       the line mark: web favicon and README
//   icon.svg       the mark on a blue tile: extension, iPhone home screen
//   icon-macos.svg the tile inside the macOS icon margin: desktop app
import { execFileSync } from "node:child_process";
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { chromium } from "../apps/extension/node_modules/playwright/index.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");

const browser = await chromium.launch();

/**
 * ### render
 *
 * Draws an SVG at a square size into a PNG with a transparent background.
 *
 * @param svgFile SVG to draw
 * @param size Width and height in pixels
 * @param out PNG to write
 */
async function render(svgFile, size, out) {
  const svg = await readFile(svgFile, "utf8");
  const page = await browser.newPage({
    viewport: { width: size, height: size },
    deviceScaleFactor: 1,
  });

  await page.setContent(
    `<html><body style="margin:0;background:transparent">${svg.replace(
      "<svg ",
      `<svg width="${size}" height="${size}" `,
    )}</body></html>`,
  );
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, await page.screenshot({ omitBackground: true }));
  await page.close();
}

const icon = join(here, "icon.svg");

if (process.argv.includes("--preview")) {
  for (const size of [16, 32, 128, 512]) {
    await render(icon, size, join(process.argv.at(-1), `preview-${size}.png`));
  }
} else {
  for (const size of [16, 32, 48, 128]) {
    await render(
      icon,
      size,
      join(root, `apps/extension/static/icons/icon-${size}.png`),
    );
  }

  await mkdir(join(root, "apps/web/public"), { recursive: true });
  // The tab icon is the bare mark, which follows the browser's colour scheme
  await copyFile(
    join(here, "mark.svg"),
    join(root, "apps/web/public/favicon.svg"),
  );
  await render(icon, 180, join(root, "apps/web/public/apple-touch-icon.png"));

  // macOS app icons sit inside a margin, so draw the tile smaller on the canvas
  const macos = join(here, "icon-macos.svg");
  const iconset = join(tmpdir(), `keymember-${process.pid}.iconset`);

  for (const size of [16, 32, 128, 256, 512]) {
    await render(macos, size, join(iconset, `icon_${size}x${size}.png`));
    await render(macos, size * 2, join(iconset, `icon_${size}x${size}@2x.png`));
  }

  await mkdir(join(root, "apps/desktop/build"), { recursive: true });
  execFileSync("iconutil", [
    "-c",
    "icns",
    iconset,
    "-o",
    join(root, "apps/desktop/build/icon.icns"),
  ]);
  await rm(iconset, { recursive: true, force: true });
}

await browser.close();
