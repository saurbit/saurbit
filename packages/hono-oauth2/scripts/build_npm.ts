import { build, emptyDir } from "jsr:@deno/dnt@0.42.3";

await emptyDir("./npm");

// Prevent npm from failing on unpublished peer deps during dnt's npm install
await Deno.writeTextFile("./npm/.npmrc", "legacy-peer-deps=true\n");

await build({
  entryPoints: ["./src/mod.ts"],
  outDir: "./npm",
  shims: {},
  package: {
    name: "@saurbit/hono-oauth2",
    version: "0.1.2",
    description: "Adapter for @saurbit/oauth2 flows in Hono applications",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/saurbit/saurbit.git",
    },
    keywords: ["oauth2", "oidc", "hono", "middleware", "adapter"],
    peerDependencies: {
      "@saurbit/oauth2": "^0.1.0",
      "hono": "^4.12.9",
    },
  },
  mappings: {
    [import.meta.resolve("@saurbit/oauth2")]: {
      name: "@saurbit/oauth2",
      version: "^0.1.0",
      peerDependency: true,
    },
    "npm:hono@^4.12.9": {
      name: "hono",
      version: "^4.12.9",
      peerDependency: true,
    },
  },
  test: false,
  typeCheck: false,
  compilerOptions: {
    lib: ["ES2021", "DOM"],
    target: "ES2021",
  },
  postBuild() {
    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
    Deno.removeSync("npm/.npmrc");
  },
});
