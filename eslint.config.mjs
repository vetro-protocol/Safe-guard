import { defineConfig, globalIgnores } from "eslint/config";
import globals from "globals";
import js from "@eslint/js";
import tseslint from "typescript-eslint";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";

export default defineConfig([
  { files: ["**/*.{js,mjs,cjs,ts}"], languageOptions: { globals: globals.node } },
  // `lib/` holds the Safe and forge-std submodules: their own prettier configs name plugins this lockfile does not
  // carry, and `eslint .` walks a real directory (the host's symlinked lib/ is skipped, a clone's is not; review G21f).
  globalIgnores(["**/typechain-types/*", "lib/**"]),
  js.configs.recommended,
  tseslint.configs.recommended,
  eslintPluginPrettierRecommended,
]);
