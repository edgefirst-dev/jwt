import { Data } from "@edgefirst-dev/data";
import { ObjectParser } from "@edgefirst-dev/data/parser";
import * as jose from "jose";
import type { Jsonifiable } from "type-fest";
import type { JWK } from "./jwk.js";

export class JWT extends Data<ObjectParser> implements jose.JWTPayload {
	/**
	 * Creates a new JWT instance with the given payload.
	 *
	 * @param payload - The payload of the JWT.
	 * @example
	 * const jwt = new JWT({ sub: "1234567890", name: "John Doe" });
	 * console.log(jwt.subject); // "1234567890"
	 */
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
	 * Gets the audience (`aud`) claim of the JWT.
	 *
	 * The "aud" (audience) claim identifies the recipients that the JWT is
	 * intended for. It can be a single string or an array of strings
	 * representing multiple audiences.
	 *
	 * @returns The audience claim or null if not present.
	 * @example
	 * const jwt = new JWT({ aud: "my-audience" });
	 * console.log(jwt.audience); // "my-audience"
	 */
	get audience() {
		if (!this.parser.has("aud")) return null;
		let value = this.parser.get("aud");
		if (typeof value === "string") return value;
		if (Array.isArray(value)) return value;
		return null;
	}

	/**
	 * Sets the audience (`aud`) claim of the JWT.
	 *
	 * The "aud" claim is used to specify the recipient(s) of the token.
	 *
	 * @param value - The audience claim to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.audience = "my-audience";
	 * console.log(jwt.audience); // "my-audience"
	 */
	set audience(value: string | string[] | null) {
		this.payload.aud = value ?? undefined;
	}

	/**
	 * Gets the expiration time (`exp`) of the JWT.
	 *
	 * The "exp" (expiration time) claim defines the time after which the JWT
	 * must not be accepted. It is represented as a Unix timestamp in seconds.
	 *
	 * @returns The expiration timestamp or null if not set.
	 * @example
	 * const jwt = new JWT({ exp: Math.floor(Date.now() / 1000) + 3600 });
	 * console.log(jwt.expiresIn); // timestamp
	 */
	get expiresIn() {
		if (this.parser.has("exp")) return this.parser.number("exp");
		return null;
	}

	/**
	 * Sets the expiration time (`exp`) of the JWT.
	 *
	 * Specifies when the JWT will expire. After this time, the token is no
	 * longer valid.
	 *
	 * @param value - The expiration timestamp to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.expiresIn = Math.floor(Date.now() / 1000) + 3600;
	 * console.log(jwt.expiresIn);
	 */
	set expiresIn(value: number | null) {
		this.payload.exp = value ?? undefined;
	}

	/**
	 * Gets the expiration date as a `Date` object.
	 *
	 * Converts the expiration timestamp (`exp`) into a `Date` object.
	 *
	 * @returns The expiration date or null if not set.
	 * @example
	 * const jwt = new JWT({ exp: Math.floor(Date.now() / 1000) + 3600 });
	 * console.log(jwt.expiresAt); // Date object
	 */
	get expiresAt() {
		if (this.expiresIn) return new Date(Date.now() + this.expiresIn);
		return null;
	}

	/**
	 * Checks if the JWT has expired.
	 *
	 * Determines if the current time is past the expiration time (`exp`).
	 *
	 * @returns True if expired, false otherwise.
	 * @example
	 * const jwt = new JWT({ exp: Math.floor(Date.now() / 1000) - 10 });
	 * console.log(jwt.expired); // true
	 */
	get expired() {
		if (this.expiresAt === null) return false;
		return this.expiresAt < new Date();
	}

	/**
	 * Gets the issued-at (`iat`) claim of the JWT.
	 *
	 * The "iat" (issued at) claim represents the time at which the token was
	 * issued. It is typically used to track when the JWT was created.
	 *
	 * @returns The issuance date or null if not set.
	 * @example
	 * const jwt = new JWT({ iat: Math.floor(Date.now() / 1000) });
	 * console.log(jwt.issuedAt); // Date object
	 */
	get issuedAt() {
		if (this.parser.has("iat")) return new Date(this.parser.number("iat"));
		return null;
	}

	/**
	 * Sets the issued-at (`iat`) claim of the JWT.
	 *
	 * Indicates the time the JWT was created.
	 *
	 * @param value - The issuance date to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.issuedAt = new Date();
	 * console.log(jwt.issuedAt);
	 */
	set issuedAt(value: Date | null) {
		this.payload.iat = value ? Math.floor(value.getTime() / 1000) : undefined;
	}

	/**
	 * Gets the issuer (`iss`) claim of the JWT.
	 *
	 * The "iss" (issuer) claim identifies the entity that issued the JWT.
	 * This is typically a URL or identifier of the authentication server.
	 *
	 * @returns The issuer or null if not set.
	 * @example
	 * const jwt = new JWT({ iss: "auth.example.com" });
	 * console.log(jwt.issuer); // "auth.example.com"
	 */
	get issuer() {
		if (this.parser.has("iss")) return this.parser.string("iss");
		return null;
	}

	/**
	 * Sets the issuer (`iss`) claim of the JWT.
	 *
	 * Identifies the entity that issued the token.
	 *
	 * @param value - The issuer to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.issuer = "auth.example.com";
	 * console.log(jwt.issuer); // "auth.example.com"
	 */
	set issuer(value: string | null) {
		this.payload.iss = value ?? undefined;
	}

	/**
	 * Gets the JWT ID (`jti`) claim.
	 *
	 * The "jti" (JWT ID) claim is a unique identifier for the token.
	 * It is often used to prevent replay attacks by ensuring each JWT has a
	 * unique ID.
	 *
	 * @returns The JWT ID or null if not set.
	 * @example
	 * const jwt = new JWT({ jti: "unique-id-123" });
	 * console.log(jwt.id); // "unique-id-123"
	 */
	get id() {
		if (this.parser.has("jti")) return this.parser.string("jti");
		return null;
	}

	/**
	 * Sets the JWT ID (`jti`) claim.
	 *
	 * Assigns a unique identifier to the token.
	 *
	 * @param value - The JWT ID to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.id = "unique-id-123";
	 * console.log(jwt.id); // "unique-id-123"
	 */
	set id(value: string | null) {
		this.payload.jti = value ?? undefined;
	}

	/**
	 * Gets the not-before (`nbf`) claim of the JWT.
	 *
	 * The "nbf" (not before) claim specifies the earliest time at which the JWT
	 * is valid. The token should not be accepted before this time.
	 *
	 * @returns The not-before date or null if not set.
	 * @example
	 * const jwt = new JWT({ nbf: Math.floor(Date.now() / 1000) + 300 });
	 * console.log(jwt.notBefore); // Date object
	 */
	get notBefore() {
		if (this.parser.has("nbf")) return new Date(this.parser.number("nbf"));
		return null;
	}

	/**
	 * Sets the not-before (`nbf`) claim of the JWT.
	 *
	 * Defines when the JWT becomes valid.
	 *
	 * @param value - The not-before date to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.notBefore = new Date(Date.now() + 300000);
	 * console.log(jwt.notBefore); // Date object
	 */
	set notBefore(value: Date | null) {
		this.payload.nbf = value ? Math.floor(value.getTime() / 1000) : undefined;
	}

	/**
	 * Gets the subject (`sub`) claim of the JWT.
	 *
	 * The "sub" (subject) claim represents the entity that the JWT is about.
	 * This is often the user ID or identifier of the authenticated entity.
	 *
	 * @returns The subject or null if not set.
	 * @example
	 * const jwt = new JWT({ sub: "user-123" });
	 * console.log(jwt.subject); // "user-123"
	 */
	get subject() {
		if (this.parser.has("sub")) return this.parser.string("sub");
		return null;
	}

	/**
	 * Sets the subject (`sub`) claim of the JWT.
	 *
	 * Defines the entity that the token is about.
	 *
	 * @param value - The subject to set.
	 * @example
	 * const jwt = new JWT();
	 * jwt.subject = "user-123";
	 * console.log(jwt.subject); // "user-123"
	 */
	set subject(value: string | null) {
		this.payload.sub = value ?? undefined;
	}

	/**
	 * Signs the JWT using the specified algorithm and key set.
	 *
	 * @param algorithm - The algorithm to use for signing.
	 * @param jwks - The key set containing private keys.
	 * @returns The signed JWT as a string.
	 * @example
	 * const jwt = new JWT({ sub: "1234567890" });
	 * const signed = await jwt.sign(JWK.Algoritm.ES256, [{ private: privateKey, alg: "RS256" }]);
	 * console.log(signed);
	 */
	sign(
		algorithm: JWK.Algoritm,
		jwks: Array<{ private: jose.KeyLike; alg: string }>,
	) {
		return JWT.sign(this, algorithm, jwks);
	}

	/**
	 * Verifies a JWT using the provided key set.
	 *
	 * @param token - The JWT to verify.
	 * @param jwks - The key set containing public keys.
	 * @param options - Optional verification options.
	 * @returns A new instance of the verified JWT payload.
	 * @throws If no valid key is found for verification.
	 * @example
	 * const verified = await JWT.verify(token, [{ public: publicKey }]);
	 * console.log(verified.subject);
	 */
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

	/**
	 * Signs a JWT instance using the given algorithm and key set.
	 *
	 * @param jwt - The JWT instance to sign.
	 * @param algorithm - The signing algorithm.
	 * @param jwks - The key set containing private keys.
	 * @returns The signed JWT as a string.
	 * @example
	 * const jwt = new JWT({ sub: "1234567890" });
	 * const signed = await JWT.sign(jwt, "RS256", [{ private: privateKey, alg: "RS256" }]);
	 * console.log(signed);
	 */
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

	/**
	 * Decodes a JWT without verifying its signature.
	 *
	 * @param token - The JWT to decode.
	 * @returns A new instance of the decoded JWT payload.
	 * @example
	 * const decoded = JWT.decode(token);
	 * console.log(decoded.subject);
	 */
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
