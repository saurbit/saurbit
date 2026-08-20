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
    version: "0.1.6",
    description: "Adapter for @saurbit/oauth2 flows in Hono applications",
    license: "MIT",
    repository: {
      type: "git",
      url: "git+https://github.com/saurbit/saurbit.git",
    },
    keywords: ["oauth2", "oidc", "hono", "middleware", "adapter"],
    peerDependencies: {
      "@saurbit/oauth2": "^0.1.8",
      "hono": "^4.13.3",
    },
  },
  mappings: {
    [import.meta.resolve("@saurbit/oauth2")]: {
      name: "@saurbit/oauth2",
      version: "^0.1.8",
      peerDependency: true,
    },
    "npm:hono@^4.13.3": {
      name: "hono",
      version: "^4.13.3",
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
    // Read the generated package.json
    const packageJson = JSON.parse(Deno.readTextFileSync("./npm/package.json"));

    // Remove hono from dependencies
    if (packageJson.dependencies?.hono) {
      delete packageJson.dependencies.hono;
    }

    // Clean up empty dependencies object
    if (Object.keys(packageJson.dependencies || {}).length === 0) {
      delete packageJson.dependencies;
    }

    // Write it back
    Deno.writeTextFileSync("./npm/package.json", JSON.stringify(packageJson, null, 2) + "\n");

    Deno.copyFileSync("LICENSE", "npm/LICENSE");
    Deno.copyFileSync("README.md", "npm/README.md");
    Deno.removeSync("npm/.npmrc");
  },
});
