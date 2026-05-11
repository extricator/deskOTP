import eslint from "@eslint/js";
import tseslint from "typescript-eslint";
import reactHooks from "eslint-plugin-react-hooks";
import jsxA11y from "eslint-plugin-jsx-a11y";
import eslintConfigPrettier from "eslint-config-prettier";

export default [
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  // Use the flat config entry from eslint-plugin-react-hooks v7
  reactHooks.configs.flat["recommended-latest"],
  {
    rules: {
      // Promoted from warn to error — required for Phase 90 hook extraction
      "react-hooks/exhaustive-deps": "error",
      // Disabled: the v7 "set-state-in-effect" rule flags the standard React pattern
      // of calling an async function from a mount-guard useEffect. The auto-trigger
      // pattern (StrictMode-safe, guarded by useRef) is correct and intentional.
      // Re-evaluate if the rule gets per-call configurability in a future release.
      "react-hooks/set-state-in-effect": "off",
    },
  },
  jsxA11y.flatConfigs.recommended,
  {
    rules: {
      // OtpCard uses div onClick with keyboard handling in parent CardGrid.
      // Full role="button" + tabIndex refactor deferred to dedicated a11y milestone.
      "jsx-a11y/click-events-have-key-events": "warn",
      "jsx-a11y/no-static-element-interactions": "warn",
      // autoFocus is used intentionally in IconPickerModal and ImportResultDialog
      // for better UX — deferred to dedicated a11y milestone.
      "jsx-a11y/no-autofocus": "warn",
      // Modal backdrop uses div onClick with target check — intentional pattern.
      "jsx-a11y/no-noninteractive-element-interactions": "warn",
    },
  },
  eslintConfigPrettier,
  {
    ignores: ["dist/**", "node_modules/**", "wailsjs/**"],
  },
];
