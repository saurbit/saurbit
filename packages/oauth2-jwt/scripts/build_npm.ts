// packages/oauth2-jwt/scripts/build_npm.ts
import { build, emptyDir } from "jsr:@deno/dnt@0.42.3";

await emptyDir("./npm");

// Prevent npm from failing on unpublished peer deps during dnt's npm install
// It restores npm v6 behavior where peer deps are advisory only and not
// automatically installed.
await Deno.writeTextFile("./npm/.npmrc", "legacy-peer-deps=true\n");

await build({
  entryPoints: ["./src/mod.ts"],
  outDir: "./npm",
  shims: {},
  package: {
    name: "@saurbit/oauth2-jwt",
    version: "0.1.3",
    description: "JWT utilities for @saurbit/oauth2 (jose-based)",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/saurbit/saurbit.git",
    },
    keywords: ["oauth2", "jwt", "jose", "jwks", "oidc"],
    peerDependencies: {
      "@saurbit/oauth2": "^0.1.1",
    },
  },
  // Map workspace imports to their npm equivalents
  mappings: {
    [import.meta.resolve("@saurbit/oauth2")]: {
      name: "@saurbit/oauth2",
      version: "^0.1.1",
      peerDependency: true,
    },
  },
  test: false,
  typeCheck: false, // skip npm install + tsc check (already checked by Deno)
  compilerOptions: {
    lib: ["ES2021", "DOM"],
    target: "ES2021",
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
    Deno.removeSync("npm/.npmrc"); // only needed during build, not publishing
  },
});
