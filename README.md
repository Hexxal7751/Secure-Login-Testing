# 🔐 Secure Login Testing

A Flask authentication demo with **username + password or Google sign-in**, **TOTP two-factor authentication** and **mandatory passkeys (WebAuthn)**, wrapped in a dark, animated, mobile-friendly UI.

**Live demo:** [sltesting.onrender.com](https://sltesting.onrender.com)

> Built for learning and demonstration. Review and test it yourself before using any part of it in production.

![Passkeys](https://img.shields.io/badge/Passkeys-Mandatory-blue)
![TOTP](https://img.shields.io/badge/2FA-TOTP-purple)
![Flask](https://img.shields.io/badge/Flask-Python-black)

## ✨ Features

- **Two ways in**: username + password (with email verification at sign-up) or "Continue with Google"
- **Three-layer sign-in**: first factor → TOTP code → passkey
- **Passkeys (WebAuthn)** required before the dashboard is reachable
- **Password reset** by emailed 8-character code (email verification only; signing in afterwards still needs TOTP and a passkey)
- **Account deletion** that re-checks every factor (password or Google, email code, TOTP, passkey) and ends with a typed confirmation
- **Rate limiting** and a temporary **account lockout** after repeated failed logins
- **CSRF tokens** on every form and passkey request
- **Strict Content-Security-Policy** with per-request nonces, plus HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` and `no-store` caching
- **Row-Level Security** policies for Supabase/Postgres (`supabase_rls_policies.sql`)
- **Security event logging** (`security_logging.py`)
- **Branded error pages** for 400/403/404/405/429/500 and more

## 🔄 Authentication flow

**New user, password path**
1. Register (username, email, password)
2. Enter the 6-digit code emailed to you (registration only)
3. Set up TOTP (scan the QR code, confirm a code)
4. Register a passkey (mandatory)
5. Dashboard

**New user, Google path**
1. Continue with Google
2. Choose a username
3. Set up TOTP
4. Register a passkey
5. Dashboard

**Returning user**: sign in with your password *or* Google → TOTP code → passkey → dashboard. No email code is needed to sign in.

**Forgot password**: Forgot your password? → enter your email → type the 8-character code and a new password → sign in as usual (TOTP, then passkey). Google accounts have no password to reset.

**Delete account** (dashboard → Delete account): password (or Google) → email code → TOTP → passkey → type `DELETE <username>` and confirm.

## 🚀 Quick start

```bash
pip install -r requirements.txt
python app.py        # http://localhost:10000
```

### Environment (`.env`)

```env
# Flask
FLASK_PASS=change-me-to-a-long-random-secret
FLASK_ENV=development            # use production on Render

# Database (Supabase / PostgreSQL connection string)
SUPABASE_URL=postgresql://username:password@host:port/database

# WebAuthn (local: localhost / http://localhost:10000)
RP_ID=yourdomain.com
ORIGIN=https://yourdomain.com

# Google sign-in (Google Cloud → OAuth web client)
# Redirect URI to register: <ORIGIN>/auth/google/callback
GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxx

# Email codes: choose ONE option
# A) AgentMail (no domain needed)
AGENTMAIL_API_KEY=am_xxxx
AGENTMAIL_INBOX=your-inbox@agentmail.to
# B) Resend (needs a domain you own)
# RESEND_API_KEY=re_xxxx
# MAIL_FROM=login@yourdomain.com
# MAIL_FROM_NAME=Secure Login Testing
```

With `FLASK_ENV=development` and no email provider set, codes are printed to the server log instead of being emailed.

> Session cookies are marked `Secure`; Chrome and Firefox treat `localhost` as secure, other hosts need HTTPS.

## 🛡️ Security summary

| Area | What the app does |
| --- | --- |
| Passwords | bcrypt (Google accounts have none) |
| Google | OpenID Connect code flow with `state` and `nonce` checks |
| 2FA | TOTP (pyotp), 6-digit codes |
| Passkeys | WebAuthn registration + authentication |
| Email codes | 6 digits (8 letters/digits for password reset), HMAC-hashed in the database, 10-minute expiry, 5 attempts, resend limits |
| Sessions | HttpOnly, Secure, SameSite=Lax, 30-minute lifetime |
| CSRF | Per-session token checked on every POST |
| Rate limits | Default 2000/day and 300/hour per IP; stricter limits on login, register, Google, email codes and deletion |
| Lockout | 5 failed logins lock the account for 15 minutes |
| Database | Parameterized queries; RLS policies provided |

Rate-limit counters are stored **in memory** (reset on restart, not shared between workers). See [SECURITY.md](./SECURITY.md).

## 🚢 Production checklist

1. `FLASK_ENV=production` (HTTPS redirect and proxy headers)
2. `RP_ID` = your domain, `ORIGIN` = its HTTPS URL
3. Long random `FLASK_PASS`
4. Add `<ORIGIN>/auth/google/callback` as an authorized redirect URI in Google Cloud
5. Configure one email provider (see above)
6. Apply `supabase_rls_policies.sql`

## 🗂️ Project structure

```
app.py                      Flask app: routes, Google, email codes, deletion, headers, errors
security_middleware.py      Input validation helpers (validate_email is used by app.py)
security_logging.py         Security event logging
supabase_rls_policies.sql   Tables and Row-Level Security policies
requirements.txt            Python dependencies
templates/                  Jinja pages (login, register, forgot/reset password, verify_email, choose_username,
                            setup/verify TOTP + passkey, dashboard, delete_account, error)
static/css/style.css        All styling (no inline styles, CSP-safe)
static/js/app.js            UI behaviour and passkey calls
```

## 🚧 Error pages

Every HTTP error is rendered by `templates/error.html` from one handler in `app.py` (`ERROR_PAGES` holds the titles and messages). Requests to `/passkey/*`, `/account/delete/passkey/*`, `/check-username` and JSON requests get `{"error": "..."}` instead of HTML.

## 📄 License

For educational and demonstration purposes.
