import { Data } from "@edgefirst-dev/data";
import { ObjectParser } from "@edgefirst-dev/data/parser";
import * as jose from "jose";
import type { Jsonifiable } from "type-fest";
import type { JWK } from "./jwk.js";

export class JWT extends Data<ObjectParser> implements jose.JWTPayload {
	constructor(public readonly payload: JWT.Payload = {}) {
		let parser = new ObjectParser(payload);
		super(parser);

		// biome-ignore lint/correctness/noConstructorReturn: We need this to correclty implement the JWT.Payload interface
		return new Proxy(this, {
			get(self, prop: string) {
				if (prop in self) return Reflect.get(self, prop);
				if (typeof prop === "string") {
					if (parser.has(prop)) return parser.get<Jsonifiable>(prop);
				}
				return null;
			},

			set(self, prop: string, value: Jsonifiable) {
				if (prop in self) return Reflect.set(self, prop, value);
				if (typeof prop === "string") {
					payload[prop] = value;
					return true;
				}
				return Reflect.set(self, prop, value);
			},
		});
	}

	[propName: string]: unknown;

	/**
	 * JWT Audience
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}
	 */
	get audience() {
		if (!this.parser.has("aud")) return null;
		let value = this.parser.get("aud");
		if (typeof value === "string") return value;
		if (Array.isArray(value)) return value;
		return null;
	}

	set audience(value: string | string[] | null) {
		this.payload.aud = value ?? undefined;
	}

	/**
	 * JWT Expiration Time
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}
	 */
	get expiresIn() {
		if (this.parser.has("exp")) return this.parser.number("exp");
		return null;
	}

	set expiresIn(value: number | null) {
		this.payload.exp = value ?? undefined;
	}

	get expiresAt() {
		if (this.expiresIn) return new Date(Date.now() + this.expiresIn);
		return null;
	}

	get expired() {
		if (this.expiresAt === null) return false;
		return this.expiresAt < new Date();
	}

	/**
	 * JWT Issued At
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 RFC7519#section-4.1.6}
	 */
	get issuedAt() {
		if (this.parser.has("iat")) return new Date(this.parser.number("iat"));
		return null;
	}

	set issuedAt(value: Date | null) {
		this.payload.iat = value ? Math.floor(value.getTime() / 1000) : undefined;
	}

	/**
	 * JWT Issuer
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
	 */
	get issuer() {
		if (this.parser.has("iss")) return this.parser.string("iss");
		return null;
	}

	set issuer(value: string | null) {
		this.payload.iss = value ?? undefined;
	}

	/**
	 * JWT ID
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}
	 */
	get id() {
		if (this.parser.has("jti")) return this.parser.string("jti");
		return null;
	}

	set id(value: string | null) {
		this.payload.jti = value ?? undefined;
	}

	/**
	 * JWT Not Before
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}
	 */
	get notBefore() {
		if (this.parser.has("nbf")) return new Date(this.parser.number("nbf"));
		return null;
	}

	set notBefore(value: Date | null) {
		this.payload.nbf = value ? Math.floor(value.getTime() / 1000) : undefined;
	}

	/**
	 * JWT Subject
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}
	 */
	get subject() {
		if (this.parser.has("sub")) return this.parser.string("sub");
		return null;
	}

	set subject(value: string | null) {
		this.payload.sub = value ?? undefined;
	}

	sign(
		algorithm: JWK.Algoritm,
		jwks: Array<{ private: jose.KeyLike; alg: string }>,
	) {
		return JWT.sign(this, algorithm, jwks);
	}

	static async verify<M extends JWT>(
		this: new (
			payload: JWT.Payload,
		) => M,
		token: string,
		jwks: Array<{ public: jose.KeyLike }>,
		options?: jose.JWTVerifyOptions,
	) {
		let key = jwks.find((key) => key.public);
		if (!key) throw new Error("No key available to verify JWT");
		let result = await jose.jwtVerify(token, key.public, options);
		// biome-ignore lint/complexity/noThisInStatic: We're doing this to allow extending the JWT class
		return new this(result.payload);
	}

	static sign(
		jwt: JWT,
		algorithm: JWK.Algoritm,
		jwks: Array<{ private: jose.KeyLike; alg: string }>,
	) {
		let key = jwks.find((key) => key.alg === algorithm);
		if (!key) {
			throw new Error(
				`No key available to sign JWT with algorithm ${algorithm}`,
			);
		}
		return new jose.SignJWT(jwt.payload)
			.setProtectedHeader({ alg: algorithm, typ: "JWT", kid: "sst" })
			.sign(key.private);
	}

	static decode<M extends JWT>(
		this: new (
			payload: JWT.Payload,
		) => M,
		token: string,
	) {
		// biome-ignore lint/complexity/noThisInStatic: We're doing this to allow extending the JWT class
		return new this(jose.decodeJwt(token));
	}
}

export namespace JWT {
	export type Payload = jose.JWTPayload;
	export type VerifyOptions = jose.JWTVerifyOptions;
}
