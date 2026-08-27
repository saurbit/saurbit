// client_capk.ts private key JWT client

import { importPKCS8, SignJWT } from "jose";

const CLIENT_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
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
/yJqaO4I3LYiNxA8+4I5uLKV4nXN
-----END PRIVATE KEY-----
`;

// sign a JWT using the private key

const privateKey = await importPKCS8(CLIENT_PRIVATE_KEY, "RS256");

const clientAssertion = await new SignJWT({ sub: "example-client" })
  .setProtectedHeader({ alg: "RS256" })
  .setJti(crypto.randomUUID()) // Set a unique JWT ID
  .setAudience("http://localhost:8000/token")
  .setSubject("example-client")
  .setIssuer("example-client")
  .setIssuedAt(Math.floor(Date.now() / 1000))
  .setExpirationTime("5m")
  .sign(privateKey);

console.log("Generated JWT:", clientAssertion);

// fetch access token using the JWT as client assertion

const tokenResponse = await fetch("http://localhost:8000/token", {
  method: "POST",
  headers: {
    "Content-Type": "application/x-www-form-urlencoded",
  },
  body: new URLSearchParams({
    client_id: "example-clientyy",
    grant_type: "client_credentials",
    client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    client_assertion: clientAssertion,
  }),
});

const tokenData = await tokenResponse.json();
console.log("Token response:", tokenData);
