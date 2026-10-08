import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";

export default defineConfig([
  { files: ["**/*.{js,mjs,cjs,ts}"], languageOptions: { globals: globals.node } },
  globalIgnores(["**/typechain-types/*"]),
  js.configs.recommended,
  tseslint.configs.recommended,
  eslintPluginPrettierRecommended,
]);
