# @saurbit/example-oak-basic

This is a basic example of using the `@saurbit/oauth2` library with the Oak framework in Deno.

## main.ts

Run the following command to start the Oak server:

```sh
deno task dev
```

## main_ca.ts

Run the following command to start the Oak server with client assertion enabled:

```sh
deno task dev:ca
```

Run the following command to start the client that uses it:

```sh
deno task start:client
```

### Generate a RSA key pair

Generate a new RSA key pair for signing and verifying JWTs. You can use the following command to
generate a new key pair:

```sh
ssh-keygen -t rsa -b 4096 -m PKCS8 -f client_assertion_rs256.key
# Don't add passphrase
openssl rsa -in client_assertion_rs256.key -pubout -outform PEM -out client_assertion_rs256.key.pub
```
