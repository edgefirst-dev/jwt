import { expect, test } from "bun:test";
import { MemoryFileStorage } from "@mjackson/file-storage/memory";
import { JWKS } from "./jwks";

const storage = new MemoryFileStorage();

test("JWKS.encryptionKeys", async () => {
	let keyPairs = await JWKS.encryptionKeys(storage);

	expect(keyPairs).toBeInstanceOf(Array);

	expect(keyPairs[0]).toEqual({
		id: expect.any(String),
		alg: "RSA-OAEP-512",
		created: expect.any(Date),
		expired: undefined,
		jwk: {
			e: expect.any(String),
			kty: "RSA",
			n: expect.any(String),
			kid: expect.any(String),
		},
		private: expect.any(CryptoKey),
		public: expect.any(CryptoKey),
	});
});

test("JWKS.signingKeys", async () => {
	let keyPairs = await JWKS.signingKeys(storage);

	expect(keyPairs).toBeInstanceOf(Array);

	expect(keyPairs[0]).toEqual({
		id: expect.any(String),
		alg: "ES256",
		created: expect.any(Date),
		expired: undefined,
		jwk: {
			crv: "P-256",
			kty: "EC",
			x: expect.any(String),
			y: expect.any(String),
			kid: expect.any(String),
			use: "sig",
		},
		private: expect.any(CryptoKey),
		public: expect.any(CryptoKey),
	});
});
