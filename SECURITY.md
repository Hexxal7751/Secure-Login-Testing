# Security Implementation

This document describes what the application actually implements, and what it does not. It is a demo project; treat it as a learning reference, not an audited product.

## Implemented

### 1. Authentication
- Password login with bcrypt hashing
- TOTP two-factor authentication (pyotp)
- Mandatory passkeys (WebAuthn) before dashboard access
- Sessions: HttpOnly, Secure, SameSite=Lax cookies; 30-minute lifetime, refreshed on activity
- `/emergency-logout` clears the session during the sign-in process

### 2. Request protection
- CSRF token required on every POST (form field `csrf_token` or `X-CSRFToken` header)
- Input validation: usernames must match `^[a-zA-Z0-9_]{3,20}$`, TOTP codes `^\d{6}$`
- Parameterized SQL queries (psycopg2)

### 3. Rate limiting and lockout (Flask-Limiter)
- Default: 200 requests/day and 50/hour per IP
- Login: 5/minute and 20/hour
- Registration: 5/minute
- TOTP setup: 5/minute
- IP lockout: 5 failed logins → blocked for 15 minutes
- Exceeding a limit shows the 429 error page

### 4. Security headers
- Content-Security-Policy with a fresh nonce per request for scripts
- Strict-Transport-Security
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin
- Permissions-Policy (camera, microphone, geolocation disabled)
- Cache-Control: no-store (responses aren't cached)

The CSP allows only same-origin resources plus `cdn.jsdelivr.net`, Google Fonts styles (`fonts.googleapis.com`) and font files (`fonts.gstatic.com`). Inline `<style>` blocks and `style=""` attributes are blocked unless they carry the nonce, so keep styling in `static/style.css`.

### 5. Database
- Row-Level Security policies in `supabase_rls_policies.sql`
- RLS context set per connection (`db_middleware.py`)

### 6. Error handling
- One handler renders all HTTP errors with fixed, generic messages
- Stack traces and exception text are never sent to the browser
- Unhandled exceptions are logged server-side and shown as a 500 page

### 7. Logging
- Security events (login success/failure, registration, lockout) go through `security_logging.py`

## Known limitations

- Rate-limit counters and IP lockouts live in memory: they reset on restart and are not shared across workers. Use a shared store (for example Redis) for multi-worker deployments.
- IP-based lockout can affect users behind a shared IP (school, office, mobile carrier NAT).
- The strict CSP is intentionally relaxed for `cdn.jsdelivr.net` and Google Fonts; remove those allowances if you self-host the assets.
- No automated security testing or third-party audit has been done.

## Guidance

### For developers
1. Use parameterized queries for all database access
2. Validate input on every new endpoint
3. Keep new CSS in `static/style.css` and new scripts nonce-tagged (`<script nonce="{{ csp_nonce }}">`)
4. Log security-relevant events with `log_security_event`

### For administrators
1. Use a long random `FLASK_PASS` and rotate it if exposed
2. Serve only over HTTPS and set `RP_ID` / `ORIGIN` correctly
3. Apply the RLS policy file to your database
4. Review logs and keep dependencies updated

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository, or contact the maintainer directly, rather than filing a public issue.
