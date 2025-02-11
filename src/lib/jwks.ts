import { Data } from "@edgefirst-dev/data";
import { ObjectParser } from "@edgefirst-dev/data/parser";
import type {
	FileStorage,
	ListOptions,
	ListResult,
} from "@mjackson/file-storage";
import * as jose from "jose";

const signingAlg = "ES256";
const encryptionAlg = "RSA-OAEP-512";

interface SerializedKeyPair {
	id: string;
	publicKey: string;
	privateKey: string;
	created: number;
	alg: string;
	expired?: number;
}

export class JWKS extends Data<ObjectParser> {
	get publicKey() {
		return this.parser.string("publicKey");
	}

	get alg() {
		return this.parser.string("alg");
	}

	get privateKey() {
		return this.parser.string("privateKey");
	}

	get id() {
		return this.parser.string("id");
	}

	get created() {
		return new Date(this.parser.number("created"));
	}

	get expired() {
		if (this.parser.has("expired")) return this.parser.date("expired");
		return undefined;
	}

	private static async *scan(storage: FileStorage, prefix: string) {
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

	static async encryptionKeys(storage: FileStorage): Promise<JWKS.KeyPair[]> {
		let results = [] as JWKS.KeyPair[];

		for await (let [fileKey] of JWKS.scan(storage, "encryption:key")) {
			if (!fileKey) continue;

			let file = await storage.get(fileKey.key);
			if (!file) continue;

			let value = new JWKS(new ObjectParser(await file.json()));

			let publicKey = await jose.importSPKI(value.publicKey, value.alg, {
				extractable: true,
			});

			let privateKey = await jose.importPKCS8(value.privateKey, value.alg);

			let jwk = await jose.exportJWK(publicKey);
			jwk.kid = value.id;

			results.push({
				id: value.id,
				alg: encryptionAlg,
				created: value.created,
				expired: value.expired ? new Date(value.expired) : undefined,
				public: publicKey,
				private: privateKey,
				jwk,
			});
		}

		results.sort((a, b) => b.created.getTime() - a.created.getTime());

		if (results.filter((item) => !item.expired).length > 0) return results;

		let key = await jose.generateKeyPair(encryptionAlg, {
			extractable: true,
		});

		let serialized = {
			id: crypto.randomUUID(),
			publicKey: await jose.exportSPKI(key.publicKey),
			privateKey: await jose.exportPKCS8(key.privateKey),
			created: Date.now(),
			alg: encryptionAlg,
		} satisfies SerializedKeyPair;

		let file = new File([JSON.stringify(serialized)], "jwks.json", {
			type: "application/json",
		});

		await storage.set(`encryption:key:${serialized.id}`, file);

		return JWKS.encryptionKeys(storage);
	}

	static async signingKeys(storage: FileStorage): Promise<JWKS.KeyPair[]> {
		let results = [] as JWKS.KeyPair[];

		for await (let [fileKey] of JWKS.scan(storage, "signing:key")) {
			if (!fileKey) continue;

			let file = await storage.get(fileKey.key);
			if (!file) continue;

			let value = new JWKS(new ObjectParser(await file.json()));

			let publicKey = await jose.importSPKI(value.publicKey, value.alg, {
				extractable: true,
			});

			let privateKey = await jose.importPKCS8(value.privateKey, value.alg);

			let jwk = await jose.exportJWK(publicKey);
			jwk.kid = value.id;
			jwk.use = "sig";

			results.push({
				id: value.id,
				alg: signingAlg,
				created: new Date(value.created),
				expired: value.expired ? new Date(value.expired) : undefined,
				public: publicKey,
				private: privateKey,
				jwk,
			});
		}

		results.sort((a, b) => b.created.getTime() - a.created.getTime());

		if (results.filter((item) => !item.expired).length > 0) return results;

		let key = await jose.generateKeyPair(signingAlg, { extractable: true });

		let serialized = {
			id: crypto.randomUUID(),
			publicKey: await jose.exportSPKI(key.publicKey),
			privateKey: await jose.exportPKCS8(key.privateKey),
			created: Date.now(),
			alg: signingAlg,
		} satisfies SerializedKeyPair;

		let file = new File([JSON.stringify(serialized)], "jwks.json", {
			type: "application/json",
		});

		await storage.set(`signing:key:${serialized.id}`, file);

		return JWKS.signingKeys(storage);
	}
}

export namespace JWKS {
	export interface KeyPair {
		id: string;
		alg: string;
		public: jose.KeyLike;
		private: jose.KeyLike;
		created: Date;
		expired?: Date;
		jwk: jose.JWK;
	}
}
