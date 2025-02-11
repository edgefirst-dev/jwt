import { Data } from "@edgefirst-dev/data";
import { ObjectParser } from "@edgefirst-dev/data/parser";
import * as jose from "jose";
import { JWKS } from "./jwks.js";

export class JWT extends Data<ObjectParser> implements jose.JWTPayload {
	constructor(readonly token: string) {
		let decoded = jose.decodeJwt(token);
		let parser = new ObjectParser(decoded);
		super(parser);

		// biome-ignore lint/correctness/noConstructorReturn: We need this to correclty implement the JWT.Payload interface
		return new Proxy(this, {
			get(self, prop: string) {
				if (prop in self) return self[prop];
				if (typeof prop === "string") {
					if (parser.has(prop)) return parser.get<unknown>(prop);
				}
				return null;
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

	/**
	 * JWT Expiration Time
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}
	 */
	get expiresIn() {
		if (this.parser.has("exp")) return this.parser.number("exp");
		return null;
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

	/**
	 * JWT Issuer
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}
	 */
	get issuer() {
		if (this.parser.has("iss")) return this.parser.string("iss");
		return null;
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

	/**
	 * JWT Not Before
	 *
	 * @see {@link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}
	 */
	get notBefore() {
		if (this.parser.has("nbf")) return new Date(this.parser.number("nbf"));
		return null;
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

	verify(jwks: JWKS.KeyPair[], options: jose.JWTVerifyOptions) {
		return JWT.verify(this.token, jwks, options);
	}

	static verify(
		token: string,
		jwks: JWKS.KeyPair[],
		options: jose.JWTVerifyOptions,
	) {
		let key = jwks.find((key) => key.public);
		if (!key) throw new Error("No key available to verify JWT");
		return jose.jwtVerify(token, key.public, options);
	}

	static sign(
		payload: jose.JWTPayload,
		algorithm: string,
		jwks: JWKS.KeyPair[],
	) {
		let key = jwks.find((key) => key.alg === algorithm);
		if (!key) {
			throw new Error(
				`No key available to sign JWT with algorithm ${algorithm}`,
			);
		}
		return new jose.SignJWT(payload)
			.setProtectedHeader({ alg: algorithm, typ: "JWT", kid: "sst" })
			.sign(key.private);
	}
}
