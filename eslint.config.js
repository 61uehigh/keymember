import js from "@eslint/js";
import { importX } from "eslint-plugin-import-x";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/dist-firefox/**",
      "eslint.config.js",
      "vitest.config.ts",
      "vitest.e2e.config.ts",
      "apps/web/vite.config.ts",
      "apps/extension/build.mjs",
      "apps/desktop/build.mjs",
      "apps/desktop/scripts/**",
      "branding/render.mjs",
    ],
  },
  js.configs.recommended,
  tseslint.configs.strictTypeChecked,
  tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      globals: globals.node,
      parserOptions: { projectService: true },
    },
    plugins: { "import-x": importX },
    rules: {
      "@typescript-eslint/array-type": ["error", { default: "generic" }],
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/consistent-type-exports": "error",
      "@typescript-eslint/no-import-type-side-effects": "error",
      "@typescript-eslint/return-await": ["error", "in-try-catch"],
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "import-x/no-cycle": "error",
      "import-x/no-duplicates": "error",
    },
  },
  {
    files: [
      "apps/web/**/*.tsx",
      "apps/web/**/*.ts",
      "apps/extension/**/*.ts",
      "apps/extension/**/*.tsx",
    ],
    languageOptions: { globals: { ...globals.browser, chrome: "readonly" } },
    plugins: { "react-hooks": reactHooks },
    rules: {
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "error",
    },
  },
);
