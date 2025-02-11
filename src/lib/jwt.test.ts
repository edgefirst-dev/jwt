import { expect, test } from "bun:test";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";
import * as jose from "jose";
import { JWKS } from "./jwks";
import { JWT } from "./jwt";

const storage = new MemoryFileStorage();

test("JWT.sign and JWT#verify", async () => {
	let payload = {
		iss: "https://example.com",
		sub: "subject",
		aud: "audience",
		jti: "id",
		exp: Math.floor(Date.now() / 1000) + 60,
		iat: Math.floor(Date.now() / 1000),
		nbf: Math.floor(Date.now() / 1000),
		uid: crypto.randomUUID(),
	} satisfies jose.JWTPayload;

	let keys = await JWKS.signingKeys(storage);

	let token = await JWT.sign(payload, "ES256", keys);

	let jwt = new JWT(token);

	await jwt.verify(keys, { audience: payload.aud, issuer: payload.iss });

	expect(jwt.issuer).toBe(payload.iss);
	expect(jwt.subject).toBe(payload.sub);
	expect(jwt.id).toBe(payload.jti);
	expect(jwt.expiresAt).toBeDate();
	expect(jwt.issuedAt).toBeDate();
	expect(jwt.notBefore).toBeDate();
	expect(jwt.expired).toBe(false);
	expect(jwt.uid).toBe(payload.uid);
});
