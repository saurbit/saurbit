import { build, emptyDir } from "jsr:@deno/dnt@0.42.3";

await emptyDir("./npm");

await build({
  entryPoints: ["./src/mod.ts"],
  outDir: "./npm",
  shims: {
    // No shims needed since the package is pure logic (no Deno-specific APIs)
  },
  package: {
    name: "@saurbit/oauth2",
    version: "0.1.0",
    description: "OAuth2 and OpenID Connect server-side flows",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/saurbit/saurbit.git",
    },
    keywords: ["oauth2", "oidc", "openid-connect"],
  },
  // Skip tests that depend on @std/assert (Deno-only)
  test: false,
  // Remove .ts extensions from imports automatically
  // scriptModule: false, // emit ESM only (no CJS script), or set to "cjs" if you want CJS
  compilerOptions: {
    lib: ["ES2021", "DOM"],
    target: "ES2021",
  },
  // Copy additional files to the output
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
  },
});