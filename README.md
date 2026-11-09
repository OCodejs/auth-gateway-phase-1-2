# OCodeJS Identity — Auth Gateway

Central identity and authentication gateway for the Velclaw ecosystem (Velclaw, Velcli, Velclawhost and OCodeJS).

> Current implementation status: Phase 1 foundation and Phase 2 email/password account/session APIs are being introduced. Google/GitHub federation and the OAuth 2.0 / OpenID Connect provider are later phases and are **not implemented yet**.

## Architecture

- `server/`: Fastify API, account identity and session handling.
- `db/migrations/`: PostgreSQL schema.
- PostgreSQL stores users, hashed session tokens and audit events.
- Passwords are hashed with Argon2id.
- Browser sessions use opaque random tokens in HttpOnly cookies; only SHA-256 token hashes are stored in the database.
- CSRF uses a signed double-submit token and exact browser-origin allowlisting.

## Requirements

- Node.js 22+
- PostgreSQL 14+
- npm

## Local setup

```bash
npm install
cp .env.example .env
```

Set `DATABASE_URL`, `SESSION_SECRET` and `CSRF_SECRET` in `.env`. Both secrets must be independent random values of at least 32 characters.

Apply the initial schema and start the API:

```bash
npm run db:migrate
npm run dev
```

The API listens on `http://localhost:3000` by default.

## Phase 1–2 API

- `GET /health` — health check.
- `GET /api/v1/auth/csrf` — returns a CSRF token and sets its cookie.
- `POST /api/v1/auth/register` — creates an account and session.
- `POST /api/v1/auth/login` — verifies email/password and creates a session.
- `GET /api/v1/me` — returns the current authenticated user.
- `POST /api/v1/auth/logout` — revokes the current session and clears its cookie.

State-changing browser requests must include cookies and the returned token in `X-CSRF-Token`.

### Browser integration example

```js
const csrf = await fetch("https://AUTH_HOST/api/v1/auth/csrf", {
  credentials: "include"
}).then((r) => r.json());

const response = await fetch("https://AUTH_HOST/api/v1/auth/login", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    "X-CSRF-Token": csrf.csrfToken
  },
  body: JSON.stringify({ email, password })
});
```

Replace `AUTH_HOST` with the real HTTPS hostname after it is assigned.

## Important deployment configuration

- Use HTTPS in production; `NODE_ENV=production` enables Secure cookies.
- Set `WEB_ORIGINS` to exact trusted origins, separated by commas. Do not use wildcard origins.
- Set `COOKIE_DOMAIN` only when the UI and API intentionally share a parent domain.
- Set independent `SESSION_SECRET` and `CSRF_SECRET` values; never commit secrets.
- Run migrations as a release step, not on every web request.
- Configure PostgreSQL backups and monitoring before production use.
- If running behind a proxy, only trust the actual hosting proxy network.

## Security and current limitations

- This phase does not yet include email verification, password-reset delivery, Google/GitHub OAuth, OIDC endpoints, application/client registry, refresh tokens, consent screens or ecosystem SSO.
- Registration currently creates an account and session immediately. Do not expose public production registration until email verification, abuse controls and account recovery are configured.
- Do not use this service as a production identity provider until the remaining phases and security tests are complete.
- Never put provider secrets or database credentials in frontend code.
