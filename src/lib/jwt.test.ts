import { expect, setSystemTime, test } from "bun:test";
import { JWT } from "./jwt";

const now = Date.now();

setSystemTime(now);

test("returns null if the JWT has no expiration time", () => {
	let jwt = new JWT({ sub: "test" });
	expect(jwt.expirationTime).toBeNull();
	expect(jwt.expiresIn).toBeNull();
	expect(jwt.expiresAt).toBeNull();
	expect(jwt.expired).toBeFalse();
});

test("returns true if it's expired", () => {
	let exp = now - 60;
	let jwt = new JWT({ exp });
	expect(jwt.expired).toBeTrue();
});

test("returns false if it's not expired", () => {
	let exp = now + 60;
	let jwt = new JWT({ exp });
	expect(jwt.expired).toBeFalse();
});

test("returns the expiration time", () => {
	let exp = now + 60;
	let jwt = new JWT({ exp });
	expect(jwt.expirationTime).toBe(exp);
});

test("returns the time remaining until expiration", () => {
	let exp = now + 60;
	let jwt = new JWT({ exp });
	expect(jwt.expiresIn).toBe(60);
});

test("returns the date when it expires", () => {
	let exp = now + 60;
	let jwt = new JWT({ exp });
	expect(jwt.expiresAt).toEqual(new Date(exp));
});
