import type {
	FileStorage,
	ListOptions,
	ListResult,
} from "@mjackson/file-storage";
import * as jose from "jose";

export namespace JWK {
	/**
	 * The possible algorithms for the JWK.
	 *
	 * - `ES256`: Used for signing keys based on ECDSA with the P-256 curve.
	 * - `RSA_OAEP_512`: Used for RSA-based encryption with OAEP padding.
	 */
	export enum Algoritm {
		ES256 = "ES256",
		RSA_OAEP_512 = "RSA-OAEP-512",
	}

	enum Prefix {
		Signing = "signing:key",
		Encryption = "encryption:key",
	}

	interface KeyPair {
		id: string;
		alg: Algoritm;
		public: jose.CryptoKey;
		private: jose.CryptoKey;
		created: Date;
		expired?: Date;
		jwk: jose.JWK;
	}

	async function* scan(storage: FileStorage, prefix: Prefix) {
		let { files, cursor } = await storage.list({ prefix, limit: 1 });
		if (!cursor) return files;
		while (cursor) {
			const result: ListResult<ListOptions> = await storage.list({
				prefix,
				cursor,
				limit: 1,
			});
			yield result.files;
			cursor = result.cursor ?? undefined;
			if (!cursor) return files;
		}
		return files;
	}

	async function storeKeyPair(
		storage: FileStorage,
		prefix: "signing:key" | "encryption:key",
		serialized: Awaited<ReturnType<typeof generateKeyPair>>,
	) {
		let file = new File([JSON.stringify(serialized)], "jwks.json", {
			type: "application/json",
		});

		await storage.set(`${prefix}:${serialized.id}`, file);
	}

	/**
	 * Imports a previously generated key pair and converts it into a usable
	 * format.
	 *
	 * This includes converting the public key into JWK format and setting key
	 * metadata.
	 *
	 * @param value - The previously generated key pair.
	 * @returns A promise that resolves to an object containing the imported key pair.
	 *
	 * @example
	 * const keyPair = await JWK.importKeyPair(existingKeyPair);
	 * console.log(keyPair.public);
	 */
	export async function importKeyPair(
		value: Awaited<ReturnType<typeof generateKeyPair>>,
	) {
		let publicKey = await jose.importSPKI(value.publicKey, value.alg, {
			extractable: true,
		});

		let privateKey = await jose.importPKCS8(value.privateKey, value.alg);

		let jwk = await jose.exportJWK(publicKey);
		jwk.kid = value.id;
		jwk.use = "sig";

		return {
			id: value.id,
			alg: Algoritm.ES256,
			created: new Date(value.created),
			expired: "expired" in value ? value.expired : undefined,
			public: publicKey,
			private: privateKey,
			jwk,
		} as KeyPair;
	}

	/**
	 * Generates a new cryptographic key pair using the specified algorithm.
	 *
	 * The keys are generated in an extractable format to allow export and import.
	 *
	 * @param alg - The algorithm to use for key generation.
	 * @returns A promise that resolves to an object containing the generated key pair.
	 *
	 * @example
	 * const keyPair = await JWK.generateKeyPair(JWK.Algoritm.ES256);
	 * console.log(keyPair);
	 */
	export async function generateKeyPair(alg: Algoritm) {
		let key = await jose.generateKeyPair(alg, { extractable: true });
		return {
			id: crypto.randomUUID(),
			publicKey: await jose.exportSPKI(key.publicKey),
			privateKey: await jose.exportPKCS8(key.privateKey),
			created: Date.now(),
			alg: alg,
		};
	}

	/**
	 * Retrieves the available signing keys from the provided file storage.
	 *
	 * If no valid signing keys exist, a new key pair is generated and stored.
	 *
	 * @param storage - The file storage system to retrieve keys from.
	 * @returns A promise that resolves to an array of signing key pairs.
	 *
	 * @example
	 * const keys = await JWK.signingKeys(storage);
	 * console.log(keys);
	 */
	export async function signingKeys(storage: FileStorage): Promise<KeyPair[]> {
		let results = [] as KeyPair[];

		for await (let [fileKey] of scan(storage, Prefix.Signing)) {
			if (!fileKey) continue;

			let file = await storage.get(fileKey.key);
			if (!file) continue;

			let data = JSON.parse(await file.text());
			results.push(await importKeyPair(data));
		}

		results.sort((a, b) => b.created.getTime() - a.created.getTime());

		if (results.filter((item) => !item.expired).length > 0) return results;

		let serialized = await generateKeyPair(Algoritm.ES256);
		await storeKeyPair(storage, Prefix.Signing, serialized);

		return signingKeys(storage);
	}

	/**
	 * Retrieves the available encryption keys from the provided file storage.
	 * If no valid encryption keys exist, a new key pair is generated and stored.
	 *
	 * @param storage - The file storage system to retrieve keys from.
	 * @returns A promise that resolves to an array of encryption key pairs.
	 *
	 * @example
	 * const keys = await JWK.encryptionKeys(storage);
	 * console.log(keys);
	 */
	export async function encryptionKeys(
		storage: FileStorage,
	): Promise<KeyPair[]> {
		let results = [] as KeyPair[];

		for await (let [fileKey] of scan(storage, Prefix.Encryption)) {
			if (!fileKey) continue;

			let file = await storage.get(fileKey.key);
			if (!file) continue;

			let data = JSON.parse(await file.text());
			results.push(await importKeyPair(data));
		}

		results.sort((a, b) => b.created.getTime() - a.created.getTime());

		if (results.filter((item) => !item.expired).length > 0) return results;

		let serialized = await generateKeyPair(Algoritm.RSA_OAEP_512);
		await storeKeyPair(storage, Prefix.Encryption, serialized);

		return encryptionKeys(storage);
	}

	/**
	 * Imports a JSON Web Key Set (JWKS) for local verification.
	 *
	 * This allows JWTs to be verified against a predefined set of public keys.
	 *
	 * @param jwks - The JSON Web Key Set containing the public keys.
	 * @param options - Optional settings, including the algorithm to use.
	 * @returns A promise that resolves to an array containing the imported public key.
	 *
	 * @example
	 * const publicKeys = await JWK.importLocal(jwks, { alg: JWK.Algoritm.ES256 });
	 * console.log(publicKeys);
	 */
	export async function importLocal(
		jwks: jose.JSONWebKeySet,
		options?: { alg: Algoritm },
	) {
		let load = jose.createLocalJWKSet(jwks);
		return [{ public: await load({ alg: options?.alg }) }];
	}

	/**
	 * Imports a JSON Web Key Set (JWKS) from a remote URL for verification.
	 *
	 * This method fetches public keys dynamically from an external endpoint.
	 *
	 * @param url - The URL of the remote JWKS endpoint.
	 * @param options - Options for fetching the keys, including the expected algorithm.
	 * @returns A promise that resolves to an array containing the imported public key.
	 *
	 * @example
	 * const publicKeys = await JWK.importRemote(new URL("https://example.com/.well-known/jwks.json"), { alg: JWK.Algoritm.ES256 });
	 * console.log(publicKeys);
	 */
	export async function importRemote(
		url: URL,
		options: jose.RemoteJWKSetOptions & { alg: Algoritm },
	) {
		let load = jose.createRemoteJWKSet(url, options);
		return [{ public: await load({ alg: options?.alg }) }];
	}

	/**
	 * Converts an array of key pairs into a JSON Web Key Set (JWKS) format.
	 *
	 * This format is commonly used for publishing public keys for JWT
	 * verification.
	 *
	 * @param keys - An array of key pairs to convert into JWKS format.
	 * @returns An object representing the JWKS structure.
	 *
	 * @example
	 * const jwks = JWK.toJSON(keyPairs);
	 * console.log(JSON.stringify(jwks, null, 2));
	 */
	export function toJSON(keys: KeyPair[]) {
		return {
			keys: keys.map(({ jwk }) => {
				return {
					crv: jwk.crv,
					kty: jwk.kty,
					x: jwk.x,
					y: jwk.y,
					kid: jwk.kid,
				};
			}),
		};
	}
}
