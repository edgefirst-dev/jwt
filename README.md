# JWT

A high-level library for working with JSON Web Tokens (JWT), making it easier to create, sign, verify, decode, and manage JWTs in your application.

## Installation

Install the library along with an implementation of the `@mjackson/file-storage`

```sh
bun add @edgefirst-dev/jwt @mjackson/file-storage
```

## Usage

### Create a JWT

Easily create a JWT instance and access claims dynamically.

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = new JWT(payload);
jwt.issuer; // Read the issuer (iss) claim
jwt.uid; // Read the uid claim
```

### Sign a JWT

To sign a JWT, you need a signing key.

```ts
import { JWT, JWK } from "@edgefirst-dev/jwt";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";

let storage = new MemoryFileStorage();

let jwt = new JWT(payload);

let token = await jwt.sign(JWK.Algoritm.ES256, await JWK.signingKeys(storage));
```

### Verify a JWT

Verify a JWT against signing keys, checking its audience and issuer

```ts
import { JWT, JWK } from "@edgefirst-dev/jwt";

let jwt = await JWT.verify(token, await JWK.signingKeys(storage), {
  audience: "api.example.com",
  issuer: "idp.example.com",
});
```

### Decode a JWT

Decode a JWT without verifying its signature.

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = JWT.decode(token);
```

### Extend the JWT class

Customize the JWT class to add custom claims or override existing ones.

```ts
import { JWT } from "@edgefirst-dev/jwt";

class CustomJWT extends JWT {
  override get issuer() {
    return this.parser.string("iss");
  }

  get userId() {
    return this.parser.string("uid");
  }
}

let customJWT = CustomJWT.decode(token);
```

### Update a JWT instance

Modify the claims of an existing JWT instance.

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = new JWT();
jwt.issuer = "new-issuer";
jwt.uid = "new-uid";
```

### Verify a JWT from Locale JWKS

You can verify a JWT using a locally managed JSON Web Key Set (JWKS).

```ts
// We need to generate and import the key pairs
let keyPair = await JWK.importKeyPair(
  await JWK.generateKeyPair(JWK.Algoritm.ES256)
);

let jwks = await JWK.importLocal(
  { keys: [keyPair.jwk] },
  { alg: JWK.Algoritm.ES256 }
);

let token = await new JWT(payload).sign(JWK.Algoritm.ES256, [keyPair]);

let jwt = await JWT.verify(token, jwks);
```

### Verify a JWT from Remote JWKS

Or you can fetch and use a remote JWKS to verify a JWT.

```ts
let jwks = await JWK.importRemote(
  new URL("https://example.com/.well-known/jwks.json"),
  { alg: JWK.Algoritm.ES256 }
);

let jwt = await JWT.verify(token, jwks);
```

### Convert JWK to JSON for well-known endpoint

To expose your JWKS in a well-known endpoint.

```ts
let keys = await JWK.signingKeys(storage);
let response = Response.json(JWK.toJSON(keys));
```
