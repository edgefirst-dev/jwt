# JWT

A library to simplify using JWT in your application.

## Usage

Install it along a library implementing `@mjackson/file-storage` interface.

```sh
bun add @edgefirst-dev/jwt @mjackson/file-storage
```

Create a new JWT

```ts
import { JWT } from "@edgefirst-dev/jwt";

let jwt = new JWT(payload);
```

You can then sign it using a signing key to get a string version.

```ts
import { JWKS } from "@edgefirst-dev/jwt";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";

const storage = new MemoryFileStorage();

let token = await jwt.sign("ES256", await JWKS.signingKeys(storage));
```

And verify it using the public key.

```ts
await jwt.verify(await JWKS.signingKeys(storage), { audience, issuer });
```

Or if you received a JWT string, you can decode it to access the payload.

```ts
let jwt = JWT.decode(token);
```

### Extending the JWT

The JWT class accepts some public claims, and allows you to use any private claim your JWT may have.

```ts
jwt.issuer; // public claim iss accessed with a more readable name
jwt.uid; // private claim uid accessed with the original name
```

Here `jwt.issuer` is a public claim saved in the JWT as `iss`, but the class gives you access to it as `issuer`. The `uid` is a private claim so you access it with the original name `uid`.

If you want to simplify using your own private claims, you can extend the JWT class.

```ts
class CustomJWT extends JWT {
  override get issuer() {
    return this.parser.string("iss");
  }

  get userId() {
    return this.parser.string("uid");
  }
}
```

Since every public claim is also marked as nullable, you could override it if you know it will always be present.

You could even use `CustomJWT.decode` to get a `CustomJWT` instance.

```ts
let jwt = CustomJWT.decode(token);
```

This way you can have a more readable and type-safe way to access your JWT claims.

### Updating the JWT

Once you have a JWT instance, you can update it with new claims.

```ts
jwt.issuer = "new-issuer";
jwt.uid = "new-uid";
```

And then sign it again.

```ts
let token = await jwt.sign("ES256", await JWKS.signingKeys(storage));
```

### Using the JWKS

The `JWKS` class is a helper to manage the JSON Web Key Set.

You can use the different static methods to create a new JWKS pair.

```ts
let jwks = await JWKS.signingKeys(storage);
```

The storage is a `FileStorage` object implementing the `@mjackson/file-storage` interface. This means JWKS can be saved as a file in the filesystem, AWS S3, Cloudflare R2, or any other storage provider.

## What to do after cloning this repository

4. Go to the Pages settings of the repo and configure it to use GitHub Actions
5. Go to the Environment settings of the repo and update the `github-pages` enviroment "Deployment branches and tags" to allow tags with the `v*.*.*` format
