import test from "node:test";
import assert from "node:assert/strict";
import { hashToken, randomToken, createCsrfToken, isValidCsrfToken } from "../server/security.js";

test("random tokens are URL-safe and contain requested entropy", () => {
  const token = randomToken(32);
  assert.match(token, /^[A-Za-z0-9_-]+$/);
  assert.equal(Buffer.from(token, "base64url").length, 32);
});
test("token hashes are deterministic and distinct from raw tokens", () => {
  const token = randomToken();
  assert.equal(hashToken(token), hashToken(token));
  assert.notEqual(hashToken(token), token);
});
test("CSRF tokens validate and reject tampering and malformed input", () => {
  const token = createCsrfToken();
  assert.equal(isValidCsrfToken(token), true);
  assert.equal(isValidCsrfToken(token + "x"), false);
  assert.equal(isValidCsrfToken("not-a-token"), false);
  assert.equal(isValidCsrfToken(""), false);
});
