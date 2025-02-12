import { expect, test } from "bun:test";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";
import { http, HttpResponse } from "msw";
import { setupServer } from "msw/native";
import { JWK, JWT } from ".";

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

test("can create a JWT", async () => {
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

test("can sign a JWT", async () => {
	let storage = new MemoryFileStorage();

	let jwt = new JWT(payload);

	let keys = await JWK.signingKeys(storage);

	let token = await jwt.sign(JWK.Algoritm.ES256, keys);

	expect(token).toBeString();
	expect(token.split(".")).toHaveLength(3);
});

test("can verify a JWT", async () => {
	let storage = new MemoryFileStorage();

	let keys = await JWK.signingKeys(storage);

	let jwt = new JWT(payload);

	let token = await jwt.sign(JWK.Algoritm.ES256, keys);

	expect(
		JWT.verify(token, keys, { audience: payload.aud, issuer: payload.iss }),
	).resolves.toBeInstanceOf(JWT);
});

test("can extend the JWT", async () => {
	class CustomJWT extends JWT {
		override get issuer() {
			return this.parser.string("iss");
		}

		get userId() {
			return this.parser.string("uid");
		}
	}

	let storage = new MemoryFileStorage();

	let token = await new CustomJWT(payload).sign(
		JWK.Algoritm.ES256,
		await JWK.signingKeys(storage),
	);

	let jwt = CustomJWT.decode(token);

	expect(jwt).toBeInstanceOf(CustomJWT);
	expect(jwt.issuer).toBe(payload.iss);
	expect(jwt.userId).toBe(payload.uid);

	expect(
		CustomJWT.verify(token, await JWK.signingKeys(storage)),
	).resolves.toBeInstanceOf(CustomJWT);
});

test("can update a JWT instance", async () => {
	let uid = crypto.randomUUID();

	let jwt = new JWT(payload);
	jwt.uid = uid;
	jwt.issuer = "https://example.org";

	expect(jwt.issuer).toBe("https://example.org");
	expect(jwt.uid).toBe(uid);
});

test("JWT.verify from local", async () => {
	let keyPair = await JWK.importKeyPair(
		await JWK.generateKeyPair(JWK.Algoritm.ES256),
	);

	let jwks = await JWK.importLocal(
		{ keys: [keyPair.jwk] },
		{ alg: JWK.Algoritm.ES256 },
	);

	let token = await new JWT(payload).sign(JWK.Algoritm.ES256, [keyPair]);

	expect(JWT.verify(token, jwks)).resolves.toBeInstanceOf(JWT);
});

test("JWT.verify from remote", async () => {
	let storage = new MemoryFileStorage();

	let signingKeys = await JWK.signingKeys(storage);

	let server = setupServer(
		http.get(
			new URL("https://example.com/.well-known/jwks.json").toString(),
			() => HttpResponse.json(JWK.toJSON(signingKeys)),
		),
	);

	server.listen();

	let token = await new JWT(payload).sign(JWK.Algoritm.ES256, signingKeys);

	let jwks = await JWK.importRemote(
		new URL("https://example.com/.well-known/jwks.json"),
		{ alg: JWK.Algoritm.ES256 },
	);

	expect(JWT.verify(token, jwks)).resolves.toBeInstanceOf(JWT);

	server.close();
});

test("can convert JWK to JSON for well-known endpoint", async () => {
	let storage = new MemoryFileStorage();

	let keys = await JWK.signingKeys(storage);

	expect(JWK.toJSON(keys)).toEqual({
		keys: [
			{
				crv: "P-256",
				kty: "EC",
				x: expect.any(String),
				y: expect.any(String),
				kid: expect.any(String),
			},
		],
	});
});
