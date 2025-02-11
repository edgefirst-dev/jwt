import { expect, test } from "bun:test";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";
import { JWKS } from "./jwks";
import { JWT } from "./jwt";

const storage = new MemoryFileStorage();

const payload = {
	iss: "https://example.com",
	sub: "subject",
	aud: "audience",
	jti: "id",
	exp: Math.floor(Date.now() / 1000) + 60,
	iat: Math.floor(Date.now() / 1000),
	nbf: Math.floor(Date.now() / 1000),
	uid: crypto.randomUUID(),
} satisfies JWT.Payload;

test("JWT constructor", () => {
	let jwt = new JWT(payload);

	expect(jwt.issuer).toBe(payload.iss);
	expect(jwt.subject).toBe(payload.sub);
	expect(jwt.id).toBe(payload.jti);
	expect(jwt.expiresAt).toBeDate();
	expect(jwt.issuedAt).toBeDate();
	expect(jwt.notBefore).toBeDate();
	expect(jwt.expired).toBe(false);
	expect(jwt.uid).toBe(payload.uid);
});

test("JWT#sign", async () => {
	let jwt = new JWT(payload);

	let token = await jwt.sign("ES256", await JWKS.signingKeys(storage));

	expect(token).toBeString();
	expect(token.split(".")).toHaveLength(3);
});

test("JWT.verify", async () => {
	let keys = await JWKS.signingKeys(storage);
	let token = await new JWT(payload).sign("ES256", keys);
	expect(
		JWT.verify(token, keys, { audience: payload.aud, issuer: payload.iss }),
	).resolves.toBeDefined();
});

test("JWT can be extended", async () => {
	class CustomJWT extends JWT {
		override get issuer() {
			return this.parser.string("iss");
		}

		get userId() {
			return this.parser.string("uid");
		}
	}

	let token = await new CustomJWT(payload).sign(
		"ES256",
		await JWKS.signingKeys(storage),
	);

	let jwt = CustomJWT.decode(token);

	expect(jwt).toBeInstanceOf(CustomJWT);
	expect(jwt.issuer).toBe(payload.iss);
	expect(jwt.userId).toBe(payload.uid);
});

test("JWT payload can be updated", async () => {
	let uid = crypto.randomUUID();

	let jwt = new JWT(payload);
	jwt.uid = uid;
	jwt.issuer = "https://example.org";

	expect(jwt.issuer).toBe("https://example.org");
	expect(jwt.uid).toBe(uid);
});
