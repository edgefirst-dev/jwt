import type {
	FileStorage,
	ListOptions,
	ListResult,
} from "@mjackson/file-storage";
import * as jose from "jose";

export namespace JWK {
	/**
	 * The possible algorithms for the JWK.
	 * The ES256 algorithm is used for signing keys.
	 * @enum
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
		public: jose.KeyLike;
		private: jose.KeyLike;
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

	export async function signingKeys(storage: FileStorage): Promise<KeyPair[]> {
		let results = [] as KeyPair[];

		for await (let [fileKey] of scan(storage, Prefix.Signing)) {
			if (!fileKey) continue;

			let file = await storage.get(fileKey.key);
			if (!file) continue;

			results.push(await importKeyPair(await file.json()));
		}

		results.sort((a, b) => b.created.getTime() - a.created.getTime());

		if (results.filter((item) => !item.expired).length > 0) return results;

		let serialized = await generateKeyPair(Algoritm.ES256);
		await storeKeyPair(storage, Prefix.Signing, serialized);

		return signingKeys(storage);
	}

	export async function encryptionKeys(
		storage: FileStorage,
	): Promise<KeyPair[]> {
		let results = [] as KeyPair[];

		for await (let [fileKey] of scan(storage, Prefix.Encryption)) {
			if (!fileKey) continue;

			let file = await storage.get(fileKey.key);
			if (!file) continue;

			results.push(await importKeyPair(await file.json()));
		}

		results.sort((a, b) => b.created.getTime() - a.created.getTime());

		if (results.filter((item) => !item.expired).length > 0) return results;

		let serialized = await generateKeyPair(Algoritm.RSA_OAEP_512);
		await storeKeyPair(storage, Prefix.Encryption, serialized);

		return encryptionKeys(storage);
	}

	export async function importLocal(
		jwks: jose.JSONWebKeySet,
		options?: { alg: Algoritm },
	) {
		let load = jose.createLocalJWKSet(jwks);
		return [{ public: await load({ alg: options?.alg }) }];
	}

	export async function importRemote(
		url: URL,
		options: jose.RemoteJWKSetOptions & { alg: Algoritm },
	) {
		let load = jose.createRemoteJWKSet(url, options);
		return [{ public: await load({ alg: options?.alg }) }];
	}

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
