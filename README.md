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
- **Recovery codes**: 8 one-time backup codes, shown once at sign-up, that replace a lost authenticator or passkey
- **Passkey manager**: list, rename, add and remove passkeys (the last one can't be removed)
- **Change password / change email**, each confirmed with emailed codes
- **Security alert emails** for password resets and changes, email changes, new or removed passkeys, recovery-code use, Google linking and account deletion
- **Signed-in devices and history**: device, approximate location and time of recent sign-ins, with "sign out" per device or everywhere else (sessions are revocable on the server)
- **Link Google** to an existing account (or unlink it), safely
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

**Account & security page** (dashboard → Account & security): change password or email, manage passkeys, regenerate recovery codes, link or unlink Google, see signed-in devices and recent sign-ins.

**Lost your phone?** On the authenticator step or the passkey step, choose "Use a recovery code". Each code works once and replaces that one factor, so replacing both uses two codes. Add a new passkey right after.

**Google + existing account**: if you sign in with Google using an email that already belongs to a password account, nothing is linked yet. Sign in to that account with your password, authenticator and passkey, and Google is linked automatically at the end.

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

# Database: Supabase -> Connect -> Session pooler connection string (port 5432).
# Render's free tier is IPv4-only, so use the pooler string, not the direct one.
# URL-encode special characters in the password (@ becomes %40, # becomes %23).
SUPABASE_URL=postgresql://postgres.<project-ref>:<password>@aws-0-<region>.pooler.supabase.com:5432/postgres

# WebAuthn (local: localhost / http://localhost:10000)
RP_ID=yourdomain.com
ORIGIN=https://yourdomain.com

# Google sign-in (Google Cloud → OAuth web client)
# Redirect URI to register: <ORIGIN>/auth/google/callback
GOOGLE_CLIENT_ID=xxxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxx

# Optional: set to off to stop looking up approximate locations of sign-ins (uses ipwho.is)
# GEOIP=off

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
| Sessions | HttpOnly, Secure, SameSite=Lax cookie, 30-minute idle lifetime, plus a server-side record that can be revoked |
| CSRF | Per-session token checked on every POST |
| Rate limits | Default 2000/day and 300/hour per IP; stricter limits on login, register, Google, email codes and deletion |
| Recovery codes | 8 per set, random 10 characters, stored only as HMAC hashes, single use |
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

## 🧰 Troubleshooting (Render logs)

| Log message | Cause and fix |
| --- | --- |
| `FATAL: (ENOTFOUND) tenant/user ... not found` | `SUPABASE_URL` is wrong, or the Supabase project is paused. Restore the project, then copy a fresh pooler string from Supabase → Connect. |
| `Google token endpoint returned 401 ... invalid_client` | `GOOGLE_CLIENT_SECRET` is wrong. Create a new secret in Google Cloud → Credentials → your Web client, copy it right away (35 characters starting `GOCSPX-`), paste it with no quotes or spaces. |
| `redirect_uri_mismatch` | The redirect URI in Google Cloud must be exactly `<ORIGIN>/auth/google/callback`. |
| `Email provider rejected the message` | Check the email API key and inbox/sender in `.env`, and the provider's sending limits. |

The app prints a configuration warning at startup (without showing any secret) when it spots an obvious mistake.

## 🗂️ Project structure

```
app.py                      Flask app: routes, Google, email codes, deletion, headers, errors
security_middleware.py      Input validation helpers (validate_email is used by app.py)
security_logging.py         Security event logging
supabase_rls_policies.sql   Tables and Row-Level Security policies
requirements.txt            Python dependencies
templates/                  Jinja pages (login, register, forgot/reset password, verify_email, choose_username,
                            account, passkeys, change_password, change_email, recovery_codes, recovery_login,
                            setup/verify TOTP + passkey, dashboard, delete_account, error)
static/css/style.css        All styling (no inline styles, CSP-safe)
static/js/app.js            UI behaviour and passkey calls
```

## 🚧 Error pages

Every HTTP error is rendered by `templates/error.html` from one handler in `app.py` (`ERROR_PAGES` holds the titles and messages). Requests to `/passkey/*`, `/account/delete/passkey/*`, `/check-username` and JSON requests get `{"error": "..."}` instead of HTML.

## 📄 License

For educational and demonstration purposes.
