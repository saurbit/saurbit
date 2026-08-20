// client_cas.ts client secret JWT client

import { SignJWT } from "jose";

const CLIENT_SECRET = `abcd1234efgh5678ijkl9012mnop3456qrst7890uvwx1234yzab5678cdef9012`;

// sign a JWT using the private key

const clientAssertion = await new SignJWT({ sub: "example-client" })
  .setProtectedHeader({ alg: "HS256" })
  .setJti(crypto.randomUUID()) // Set a unique JWT ID
  .setAudience("http://localhost:8000/token")
  .setSubject("example-client")
  .setIssuer("example-client")
  .setIssuedAt(Math.floor(Date.now() / 1000))
  .setExpirationTime("5m")
  .sign(new TextEncoder().encode(CLIENT_SECRET));

console.log("Generated JWT:", clientAssertion);

// fetch access token using the JWT as client assertion

const tokenResponse = await fetch("http://localhost:8000/token", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: new URLSearchParams({
    grant_type: "client_credentials",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: clientAssertion,
  }),
});

const tokenData = await tokenResponse.json();
console.log("Token response:", tokenData);
