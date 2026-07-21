import js from "@eslint/js";
import tseslint from "typescript-eslint";
import jsxA11y from "eslint-plugin-jsx-a11y";
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
      "jsx-a11y": jsxA11y,
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...jsxA11y.flatConfigs.recommended.rules,
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],
      "jsx-a11y/label-has-associated-control": [
        "error",
        {
          controlComponents: ["Input", "Switch", "Textarea"],
        },
      ],
      // Dialogs and command surfaces intentionally move focus to the primary
      // input when they open.
      "jsx-a11y/no-autofocus": "off",
      // React 19's hooks plugin added set-state-in-effect and refs-during-render
      // as errors. In a Tauri desktop app there's no Suspense or RSC, so loading
      // data from the Rust backend via setState-in-useEffect is the standard
      // pattern. These are legitimate code-quality signals, not bugs — downgrade
      // to warnings so they surface without blocking the build.
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/refs": "warn",
    },
  },

  // These components intentionally attach keyboard or mouse handling to
  // non-button containers while preserving a separate accessible control.
  {
    files: [
      "src/components/PendingApprovals.tsx",
      "src/components/RegistryServerRow.tsx",
    ],
    rules: {
      "jsx-a11y/click-events-have-key-events": "off",
      "jsx-a11y/no-noninteractive-element-interactions": "off",
      "jsx-a11y/no-static-element-interactions": "off",
    },
  },

  // Turn off all rules that conflict with Prettier (formatting concerns).
  prettierConfig,
);
