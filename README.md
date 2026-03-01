# Saurbit

A monorepo for developing and maintaining modular, reusable **backend** packages built with [Deno](https://deno.land/).

## Structure

```
saurbit/
├── packages/    # Deno packages (each with its own deno.json)
├── examples/    # Standalone usage examples
├── deno.json    # Workspace root config
└── LICENSE
```

## Getting Started

**Prerequisites:** [Deno v2+](https://docs.deno.com/runtime/getting_started/installation/)

```sh
# check all packages
deno task check

# run all tests
deno task test

# lint & format
deno task lint
deno task fmt
```

## Adding a Package

Create a new directory under `packages/` with its own `deno.json`:

```
packages/my-package/
├── deno.json
├── mod.ts
└── mod_test.ts
```

The root workspace in `deno.json` automatically picks up any directory under `packages/*`.

## Adding an Example

Create a new directory under `examples/` with its own `deno.json` that imports from local packages:

```
examples/my-example/
├── deno.json
└── main.ts
```

## License

[MIT](LICENSE) &copy; saurbit
