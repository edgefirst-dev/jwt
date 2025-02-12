# JWT

A library to simplify using JWT in your application.

## Usage

Install it along a library implementing `@mjackson/file-storage` interface.

```sh
bun add @edgefirst-dev/jwt @mjackson/file-storage
```

### Create a JWT

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = new JWT(payload);
jwt.issuer; // Read the issuer (iss) claim
jwt.uid; // Read the uid claim
```

### Sign a JWT

```ts
import { JWT, JWK } from "@edgefirst-dev/jwt";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";

let storage = new MemoryFileStorage();

let jwt = new JWT(payload);

let token = await jwt.sign(JWK.Algoritm.ES256, await JWK.signingKeys(storage));
```

### Verify a JWT

```ts
import { JWT, JWK } from "@edgefirst-dev/jwt";

let jwt = await JWT.verify(token, await JWK.signingKeys(storage), {
  audience: "api.example.com",
  issuer: "idp.example.com",
});
```

### Decode a JWT

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = JWT.decode(token);
```

### Extend the JWT class

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

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = new JWT();
jwt.issuer = "new-issuer";
jwt.uid = "new-uid";
```

### Verify a JWT from Locale JWKS

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

```ts
let jwks = await JWK.importRemote(
  new URL("https://example.com/.well-known/jwks.json"),
  { alg: JWK.Algoritm.ES256 }
);

let jwt = await JWT.verify(token, jwks);
```

### Convert JWK to JSON for well-known endpoint

```ts
let keys = await JWK.signingKeys(storage);
let response = Response.json(JWK.toJSON(keys));
```
