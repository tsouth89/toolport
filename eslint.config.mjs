import js from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import prettierConfig from "eslint-config-prettier";
import globals from "globals";

export default tseslint.config(
  // Ignore build output and deps (Prettier handles its own ignores).
  {
    ignores: ["dist/", "node_modules/", "src-tauri/"],
  },

  // Base JS + TypeScript recommended rules.
  js.configs.recommended,
  ...tseslint.configs.recommended,

  // Project source files.
  {
    files: ["src/**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
      parserOptions: {
        ecmaFeatures: { jsx: true },
      },
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      // React 19's hooks plugin added set-state-in-effect and refs-during-render
      // as errors. In a Tauri desktop app there's no Suspense or RSC, so loading
      // data from the Rust backend via setState-in-useEffect is the standard
      // pattern. These are legitimate code-quality signals, not bugs — downgrade
      // to warnings so they surface without blocking the build.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/refs": "warn",
    },
  },

  // Turn off all rules that conflict with Prettier (formatting concerns).
  prettierConfig,
);
