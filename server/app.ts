import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import cookie from "@fastify/cookie";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import argon2 from "argon2";
import { z } from "zod";
import { pool } from "./db.js";
import { config } from "./config.js";
import { createCsrfToken, hashToken, isValidCsrfToken, randomToken } from "./security.js";

const SESSION_COOKIE = "ocodejs_session";
const CSRF_COOKIE = "ocodejs_csrf";
const emailSchema = z.string().trim().email().max(254);
const credentialsSchema = z.object({
  email: emailSchema,
  password: z.string().min(12).max(128)
});

type SessionUser = { id: string; email: string; email_verified: boolean };

declare module "fastify" {
  interface FastifyRequest {
    authUser: SessionUser | null;
  }
}

function cookieOptions(httpOnly: boolean) {
  return {
    path: "/",
    httpOnly,
    secure: config.secureCookies,
    sameSite: "lax" as const,
    ...(config.COOKIE_DOMAIN ? { domain: config.COOKIE_DOMAIN } : {}),
    ...(httpOnly ? { maxAge: config.SESSION_TTL_SECONDS } : { maxAge: 3600 })
  };
}

function clientIp(request: FastifyRequest): string | null {
  return request.ip || null;
}

async function audit(request: FastifyRequest, event: string, userId: string | null = null) {
  await pool.query(
    "INSERT INTO audit_logs(user_id,event_type,ip_address,user_agent) VALUES($1,$2,$3,$4)",
    [userId, event, clientIp(request), request.headers["user-agent"] ?? null]
  );
}

function requireCsrf(request: FastifyRequest, reply: FastifyReply): boolean {
  const cookieToken = request.cookies[CSRF_COOKIE];
  const headerToken = request.headers["x-csrf-token"];
  if (
    typeof cookieToken !== "string" ||
    typeof headerToken !== "string" ||
    cookieToken !== headerToken ||
    !isValidCsrfToken(cookieToken)
  ) {
    void reply.code(403).send({ error: "csrf_failed", message: "CSRF validation failed" });
    return false;
  }
  return true;
}

async function createSession(request: FastifyRequest, reply: FastifyReply, userId: string) {
  const rawToken = randomToken(48);
  const expiresAt = new Date(Date.now() + config.SESSION_TTL_SECONDS * 1000);
  await pool.query(
    "INSERT INTO user_sessions(user_id,token_hash,expires_at,user_agent,ip_address) VALUES($1,$2,$3,$4,$5)",
    [userId, hashToken(rawToken), expiresAt, request.headers["user-agent"] ?? null, clientIp(request)]
  );
  reply.setCookie(SESSION_COOKIE, rawToken, cookieOptions(true));
}

const app = Fastify({
  logger: true,
  trustProxy: config.NODE_ENV === "production",
  bodyLimit: 16 * 1024
});

await app.register(cookie);
await app.register(cors, {
  credentials: true,
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-CSRF-Token"],
  origin(origin, callback) {
    if (!origin || config.webOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Origin not allowed"), false);
  }
});
await app.register(rateLimit, {
  global: true,
  max: 100,
  timeWindow: "1 minute"
});

app.decorateRequest("authUser", null);

app.addHook("preHandler", async (request) => {
  request.authUser = null;
  const rawToken = request.cookies[SESSION_COOKIE];
  if (typeof rawToken !== "string") return;

  const result = await pool.query<{
    id: string; email: string; email_verified_at: Date | null;
  }>(
    `SELECT u.id,u.email,u.email_verified_at
       FROM user_sessions s JOIN users u ON u.id=s.user_id
      WHERE s.token_hash=$1 AND s.expires_at > now() AND u.status='active'
      LIMIT 1`,
    [hashToken(rawToken)]
  );
  const user = result.rows[0];
  if (!user) return;
  request.authUser = {
    id: user.id,
    email: user.email,
    email_verified: Boolean(user.email_verified_at)
  };
  void pool.query("UPDATE user_sessions SET last_seen_at=now() WHERE token_hash=$1", [hashToken(rawToken)]);
});

app.get("/health", async () => ({ status: "ok", service: "ocodejs-auth-gateway" }));

app.get("/api/v1/auth/csrf", async (_request, reply) => {
  const token = createCsrfToken();
  reply.setCookie(CSRF_COOKIE, token, cookieOptions(false));
  return { csrfToken: token };
});

app.post("/api/v1/auth/register", {
  config: { rateLimit: { max: 5, timeWindow: "15 minutes" } }
}, async (request, reply) => {
  if (!requireCsrf(request, reply)) return;
  const parsed = credentialsSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: "invalid_input", details: parsed.error.flatten() });

  const email = parsed.data.email;
  const normalized = email.toLowerCase();
  const passwordHash = await argon2.hash(parsed.data.password, { type: argon2.argon2id });
  try {
    const inserted = await pool.query<{ id: string }>(
      "INSERT INTO users(email,email_normalized,password_hash) VALUES($1,$2,$3) RETURNING id",
      [email, normalized, passwordHash]
    );
    const userId = inserted.rows[0]!.id;
    await createSession(request, reply, userId);
    await audit(request, "account.registered", userId);
    return reply.code(201).send({
      user: { id: userId, email, email_verified: false },
      notice: "Account created. Email verification will be enabled when the mail delivery provider is configured."
    });
  } catch (error: unknown) {
    if (typeof error === "object" && error !== null && "code" in error && error.code === "23505") {
      return reply.code(409).send({ error: "account_exists", message: "An account with this email already exists." });
    }
    throw error;
  }
});

app.post("/api/v1/auth/login", {
  config: { rateLimit: { max: 10, timeWindow: "15 minutes" } }
}, async (request, reply) => {
  if (!requireCsrf(request, reply)) return;
  const parsed = credentialsSchema.safeParse(request.body);
  if (!parsed.success) return reply.code(400).send({ error: "invalid_credentials", message: "Invalid email or password." });

  const result = await pool.query<{ id: string; email: string; password_hash: string; status: string }>(
    "SELECT id,email,password_hash,status FROM users WHERE email_normalized=$1 LIMIT 1",
    [parsed.data.email.toLowerCase()]
  );
  const user = result.rows[0];
  const valid = user && user.status === "active"
    ? await argon2.verify(user.password_hash, parsed.data.password).catch(() => false)
    : false;
  if (!valid || !user) {
    await audit(request, "auth.login_failed");
    return reply.code(401).send({ error: "invalid_credentials", message: "Invalid email or password." });
  }

  await pool.query("DELETE FROM user_sessions WHERE user_id=$1 AND expires_at <= now()", [user.id]);
  await createSession(request, reply, user.id);
  await pool.query("UPDATE users SET last_login_at=now() WHERE id=$1", [user.id]);
  await audit(request, "auth.login_succeeded", user.id);
  return { user: { id: user.id, email: user.email } };
});

app.get("/api/v1/me", async (request, reply) => {
  if (!request.authUser) return reply.code(401).send({ error: "unauthenticated" });
  return { user: request.authUser };
});

app.post("/api/v1/auth/logout", async (request, reply) => {
  if (!requireCsrf(request, reply)) return;
  const rawToken = request.cookies[SESSION_COOKIE];
  if (typeof rawToken === "string") {
    await pool.query("DELETE FROM user_sessions WHERE token_hash=$1", [hashToken(rawToken)]);
  }
  reply.clearCookie(SESSION_COOKIE, { path: "/", ...(config.COOKIE_DOMAIN ? { domain: config.COOKIE_DOMAIN } : {}) });
  await audit(request, "auth.logout", request.authUser?.id ?? null);
  return { ok: true };
});

app.setErrorHandler((error, request, reply) => {
  request.log.error({ err: error }, "Request failed");
  if (reply.sent) return;
  return reply.code(500).send({ error: "internal_error", message: "An unexpected error occurred." });
});

export { app };
