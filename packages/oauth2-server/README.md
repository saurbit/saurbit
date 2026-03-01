# @saurbit/oauth2-server

A framework-agnostic [OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc6749) authorization server
implementation for [Deno](https://deno.land/).

## Features

- **Authorization Code** grant (with PKCE support)
- **Client Credentials** grant
- **Refresh Token** grant
- Framework-agnostic - bring your own HTTP layer
- Pluggable model interface for storage

## Quick Start

```ts
import { OAuth2Server } from "@saurbit/oauth2-server";

const server = new OAuth2Server({
  model: {
    // implement the model interface for your storage layer
  },
});
```

## License

[MIT](../../LICENSE)
