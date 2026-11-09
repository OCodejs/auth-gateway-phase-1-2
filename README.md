# OCodeJS Identity — Auth Gateway

Central identity and authentication gateway for the Velclaw ecosystem (Velclaw, Velcli, Velclawhost and OCodeJS).

> Current implementation: Phase 1–2 foundation, email/password accounts, email verification, password reset and browser session APIs. Google/GitHub federation and the OAuth 2.0 / OpenID Connect provider are later phases and are not implemented yet.

## Architecture

- Fastify API and PostgreSQL persistence.
- Passwords are hashed with Argon2id.
- Browser sessions use opaque random tokens in HttpOnly cookies; only SHA-256 token hashes are stored.
- Email verification and password-reset tokens are random, single-use, expire after 30 minutes, and are stored as hashes.
- CSRF uses a signed double-submit token and exact browser-origin allowlisting.
- SMTP delivers verification and password-reset emails. In development without SMTP, links are logged to the server console only.

## Requirements and setup

- Node.js 22+
- PostgreSQL 14+
- SMTP credentials for production email delivery

```bash
npm install
cp .env.example .env
```

Configure `DATABASE_URL`, independent `SESSION_SECRET` and `CSRF_SECRET` values (at least 32 characters), `APP_BASE_URL`, exact `WEB_ORIGINS`, and SMTP settings. In production, `SMTP_HOST` is mandatory.

```bash
npm run db:migrate
npm run dev
```

The API listens on `http://localhost:3000` by default. Migrations are ordered and tracked in `schema_migrations`; they are safe to rerun.

## API

- `GET /health` — health check.
- `GET /api/v1/auth/csrf` — issues CSRF cookie and token.
- `POST /api/v1/auth/register` — creates an unverified account and sends verification email. No session is created.
- `POST /api/v1/auth/verify-email` — consumes a single-use verification token.
- `POST /api/v1/auth/resend-verification` — sends a new verification link; response does not reveal account existence.
- `POST /api/v1/auth/login` — email/password login; verified email is required.
- `POST /api/v1/auth/request-password-reset` — requests a reset link with a non-enumerating response.
- `POST /api/v1/auth/reset-password` — consumes a single-use reset token, changes the password and revokes all sessions.
- `GET /api/v1/me` — returns the current authenticated user.
- `POST /api/v1/auth/logout` — revokes the current session and clears its cookie.

All state-changing browser requests must first call the CSRF endpoint, send cookies with `credentials: "include"`, and include the returned value in `X-CSRF-Token`.

## Frontend integration

The existing `index.html` now calls the API for login, registration, email verification, resend verification and password reset. By default it expects the API on the same origin. If the UI is hosted separately, define `window.AUTH_API_BASE = "https://<auth-host>"` before the page script and add the exact UI origin to `WEB_ORIGINS`. Configure `APP_BASE_URL` as the public URL where the UI handles the verification/reset query parameters.

## CI and local checks

```bash
npm run typecheck
npm test
npm run build
```

GitHub Actions runs these checks on pull requests and pushes to `main`. The current automated unit tests cover token generation, token hashing and CSRF validation; they do not replace integration tests against a real PostgreSQL instance and SMTP sandbox.

## Production safety

- Use HTTPS; `NODE_ENV=production` enables Secure cookies.
- Never use wildcard CORS origins with credentials.
- Set `COOKIE_DOMAIN` only when UI and API intentionally share a parent domain.
- Configure PostgreSQL backups, monitoring, SMTP deliverability and proxy trust settings before production.
- Public registration should remain disabled until deployment-level abuse controls, monitoring and mail delivery have been verified.
- Do not put provider secrets or database credentials in frontend code.
- Google/GitHub OAuth, OIDC issuer endpoints, client registry, consent, refresh tokens and ecosystem SSO are not implemented yet.
