import js from "@eslint/js";
import globals from "globals";

export default [
  {
    ignores: [
      "dist/**", ".tools/**", "node_modules/**", "coverage/**", "test-results/**",
      "companion/**", "server/**"
    ]
  },
  js.configs.recommended,
  {
    // Extension code: ES modules running in an MV3 service worker (Chromium),
    // an event page (Firefox) or extension pages. No Node globals.
    files: ["src/**/*.js", "*.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.browser, ...globals.serviceworker, ...globals.webextensions }
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrors: "none" }],
      "no-console": "off",
      "eqeqeq": ["error", "smart"],
      "no-implicit-globals": "error",
      "prefer-const": "error"
    }
  },
  {
    files: ["test/**/*.mjs", "scripts/**/*.mjs", "icons/**/*.mjs", "eslint.config.js"],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.node }
    },
    rules: {
      "no-unused-vars": ["error", { argsIgnorePattern: "^_", caughtErrors: "none" }]
    }
  }
];
