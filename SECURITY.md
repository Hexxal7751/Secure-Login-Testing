# Security Implementation

This document describes what the application actually implements, and what it does not. It is a demo project; treat it as a learning reference, not an audited product.

## Implemented

### 1. Authentication
- Password login with bcrypt hashing, or Google sign-in (OpenID Connect authorization-code flow with `state` and `nonce`, verified email required)
- Email verification code at registration (password path only)
- TOTP two-factor authentication (pyotp)
- Mandatory passkeys (WebAuthn) before dashboard access
- TOTP cannot be re-created from a half-signed-in session, and extra passkeys can only be added after a passkey login
- Sessions: HttpOnly, Secure, SameSite=Lax cookies; 30-minute lifetime, refreshed on activity
- `/emergency-logout` clears the session during the sign-in process

### 2. Password reset
- Email-only verification: an 8-character code (letters and digits, no look-alikes) sent to the verified email of a password account
- The page answers the same way whether or not the email exists; Google-only accounts get no code
- Same code protections as below (HMAC-hashed, single use, 10-minute expiry, 5 attempts, resend limits); a successful reset also clears any lockout
- Resetting the password does not bypass TOTP or the passkey: both are still required to sign in

### 3. Account deletion
- Requires a fully signed-in session, then re-verifies: password (or Google account), emailed code, TOTP code and a passkey (user verification required)
- Finishes with a typed phrase and a confirmation dialog; the whole flow expires after 10 minutes and is cancelled after 5 wrong answers
- Deletes the account, passkeys and email codes in one transaction

### 4. Email codes
- 6 random digits (8 letters/digits for password reset), stored only as an HMAC (keyed with `FLASK_PASS`), single use
- 10-minute expiry, 5 attempts per code, 45 seconds between sends, 5 codes per hour
- Sent through an HTTPS email API (AgentMail or Resend); codes are never logged in production

### 5. Request protection
- CSRF token required on every POST (form field `csrf_token` or `X-CSRFToken` header)
- Input validation: usernames `^[a-zA-Z0-9_]{3,20}$`, codes `^\d{6}$`, passwords 8 to 72 bytes
- Parameterized SQL queries (psycopg2)

### 6. Rate limiting and lockout (Flask-Limiter)
- Default: 2000 requests/day and 300/hour per IP
- Login 5/minute and 20/hour; registration 5/minute; password reset 5/minute and 15/hour; TOTP setup 10/minute; email code 15/minute; Google 15-20/minute; deletion 40/hour (POST requests only)
- Account lockout: 5 failed password logins lock the account for 15 minutes
- Exceeding a limit shows the 429 error page

### 7. Security headers
- Content-Security-Policy with a fresh nonce per request for scripts and styles
- Strict-Transport-Security, X-Frame-Options: DENY, X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin-when-cross-origin, Permissions-Policy, Cache-Control: no-store

The CSP allows only same-origin resources plus `cdn.jsdelivr.net`, Google Fonts styles and font files. Inline `<style>` blocks and `style=""` attributes are blocked unless nonce-tagged, so keep styling in `static/css/style.css`.

### 8. Database
- Row-Level Security policies in `supabase_rls_policies.sql`
- The app sets `app.current_user_id` (or `app.is_admin` for registration, lookups and deletion) on each connection

### 9. Error handling and logging
- One handler renders all HTTP errors with fixed, generic messages; exception text is never sent to the browser
- Security events (login success/failure, registration, lockout, password reset, account deletion) go through `security_logging.py`

## Known limitations

- Rate-limit counters live in memory: they reset on restart and are not shared across workers (use Redis for multi-worker setups).
- Google's ID token is trusted without a signature check because it is received directly from Google over HTTPS with the client secret (as Google documents).
- The re-confirmation of a Google account for deletion checks the same Google account is chosen; it does not force Google to ask for the password again.
- Free email plans cap recipients and volume; codes can fail to send if the provider limit is reached.
- No automated security testing or third-party audit has been done.

## Guidance

### For developers
1. Use parameterized queries for all database access
2. Validate input on every new endpoint
3. Keep new CSS in `static/css/style.css` and new scripts nonce-tagged (`<script nonce="{{ csp_nonce }}">`)
4. Log security-relevant events with `log_security_event`

### For administrators
1. Use a long random `FLASK_PASS` (changing it also invalidates pending email codes) and rotate it if exposed
2. Serve only over HTTPS and set `RP_ID` / `ORIGIN` correctly
3. Keep `GOOGLE_CLIENT_SECRET` and the email API key out of Git
4. Apply the RLS policy file to your database and keep dependencies updated

## Reporting a vulnerability

Please open a private security advisory on the GitHub repository, or contact the maintainer directly, rather than filing a public issue.
