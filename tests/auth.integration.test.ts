import test from "node:test";
import assert from "node:assert/strict";
import { app } from "../server/app.js";
import { pool } from "../server/db.js";

test("registration requires verification before a password session can be created", async () => {
  const email = `integration-${Date.now()}@example.com`;
  const csrfResponse = await app.inject({ method: "GET", url: "/api/v1/auth/csrf" });
  assert.equal(csrfResponse.statusCode, 200);
  const csrfToken = csrfResponse.json<{csrfToken:string}>().csrfToken;
  const setCookie = csrfResponse.headers["set-cookie"];
  const cookieHeader = (Array.isArray(setCookie) ? setCookie[0] : setCookie)?.split(";")[0];
  assert.ok(cookieHeader);

  try {
    const register = await app.inject({
      method: "POST", url: "/api/v1/auth/register",
      headers: { cookie: cookieHeader, "x-csrf-token": csrfToken },
      payload: { email, password: "integration-password-123" }
    });
    assert.equal(register.statusCode, 201);
    assert.equal(register.json().verification_required, true);

    const login = await app.inject({
      method: "POST", url: "/api/v1/auth/login",
      headers: { cookie: cookieHeader, "x-csrf-token": csrfToken },
      payload: { email, password: "integration-password-123" }
    });
    assert.equal(login.statusCode, 403);
    assert.equal(login.json().error, "email_not_verified");

    const me = await app.inject({ method: "GET", url: "/api/v1/me" });
    assert.equal(me.statusCode, 401);
  } finally {
    await pool.query("DELETE FROM users WHERE email_normalized=$1", [email]);
  }
});
