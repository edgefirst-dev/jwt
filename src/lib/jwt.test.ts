import { expect, test } from "bun:test";
import { JWT } from "./jwt";

test("returns null if the JWT has no expiration time", () => {
	let jwt = new JWT({ sub: "test" });
	expect(jwt.expiresIn).toBeNull();
	expect(jwt.expiresAt).toBeNull();
	expect(jwt.expired).toBeFalse();
});

test("returns true if it's expired", () => {
	let jwt = new JWT({ exp: Date.now() - 60 });
	expect(jwt.expired).toBeTrue();
});

test("returns false if it's not expired", () => {
	let jwt = new JWT({ exp: Date.now() + 60 });
	expect(jwt.expired).toBeFalse();
});
