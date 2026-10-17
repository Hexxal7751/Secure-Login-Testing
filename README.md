# 🔐 Secure Login Testing

A Flask authentication demo that combines **username + password**, **TOTP two-factor authentication** and **mandatory passkeys (WebAuthn)**, wrapped in a dark, animated, mobile-friendly UI.

**Live demo:** [sltesting.onrender.com](https://sltesting.onrender.com)

> Built for learning and demonstration. Review and test it yourself before using any part of it in production.

![Passkeys](https://img.shields.io/badge/Passkeys-Mandatory-blue)
![TOTP](https://img.shields.io/badge/2FA-TOTP-purple)
![Flask](https://img.shields.io/badge/Flask-Python-black)

## ✨ Features

- **Three-layer sign-in**: password → TOTP code → passkey
- **Passkeys (WebAuthn)** required before the dashboard is reachable
- **Rate limiting** and a temporary **IP lockout** after repeated failed logins
- **CSRF tokens** on every form and passkey request
- **Strict Content-Security-Policy** with per-request nonces, plus HSTS, `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy` and `no-store` caching
- **Row-Level Security** policies for Supabase/Postgres (`supabase_rls_policies.sql`)
- **Security event logging** (`security_logging.py`)
- **Responsive, touch-friendly UI** with reduced-motion support
- **Branded error pages** for 400/403/404/405/429/500 and more

## 🔄 Authentication flow

**New user**

1. Register with a username and password
2. Log in
3. Set up TOTP (scan the QR code, confirm a 6-digit code)
4. Register a passkey (mandatory)
5. Dashboard

**Returning user**

1. Log in with username and password
2. Verify the TOTP code
3. Verify with your passkey (or set one up if you haven't yet)
4. Dashboard

```
Register → Login → TOTP setup → TOTP verify → Passkey → Dashboard
```

## 🚀 Quick start

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Configure

Create a `.env` file:

```env
# Flask
FLASK_PASS=change-me-to-a-long-random-secret
FLASK_ENV=development

# Database (Supabase / PostgreSQL connection string)
SUPABASE_URL=postgresql://username:password@host:port/database

# WebAuthn
# Local development:
RP_ID=localhost
ORIGIN=http://localhost:10000
# Production example:
# RP_ID=yourdomain.com
# ORIGIN=https://yourdomain.com
```

### 3. Run

```bash
python app.py
```

Open <http://localhost:10000>.

> Session cookies are marked `Secure`, so some browsers won't keep the session over plain `http://`. Chrome and Firefox treat `localhost` as secure; if you test on another host, use HTTPS.

## 🛡️ Security summary

| Area | What the app does |
| --- | --- |
| Passwords | Hashed with bcrypt |
| 2FA | TOTP (pyotp), 6-digit codes |
| Passkeys | WebAuthn registration + authentication |
| Sessions | HttpOnly, Secure, SameSite=Lax, 30-minute lifetime |
| CSRF | Per-session token checked on every POST |
| Rate limits | Default 200/day and 50/hour per IP; login 5/min and 20/hour; register 5/min; TOTP setup 5/min |
| Lockout | 5 failed logins from an IP → blocked for 15 minutes |
| Headers | CSP (nonce-based scripts), HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy |
| Database | Parameterized queries; RLS policies provided |

Rate-limit counters and IP lockouts are stored **in memory**, so they reset when the server restarts and aren't shared between multiple workers. See [SECURITY.md](./SECURITY.md) for details and known limitations.

## 🌐 Browser support

Passkeys work on Chrome 67+, Safari 13+ and Edge 18+ (desktop and mobile), and Firefox 60+ (desktop).

## 🚢 Production checklist

1. Set `FLASK_ENV=production` (enables HTTPS redirect and proxy headers)
2. Set `RP_ID` to your domain and `ORIGIN` to its HTTPS URL
3. Use a long, random `FLASK_PASS`
4. Serve over HTTPS
5. Apply `supabase_rls_policies.sql` to your database

## 🗂️ Project structure

```
app.py                      Flask app, routes, security headers, error handling
db_middleware.py            Database / RLS context helpers
security_middleware.py      Input validation helpers
security_logging.py         Security event logging
supabase_rls_policies.sql   Row-Level Security policies
templates/                  Jinja pages (login, register, TOTP, passkey, dashboard, error.html)
static/style.css            All styling (no inline styles, CSP-safe)
```

## 🎨 UI notes

- Dark glass theme with gradients, animated stepper, OTP input and passkey orb
- Fonts: Plus Jakarta Sans and JetBrains Mono (system fonts as fallback)
- **All CSS lives in `static/style.css`.** The CSP blocks inline `<style>` and `style=""`, so don't add them; put new rules in the stylesheet.
- On phones and touch devices the UI drops the heaviest effects (large blur filters, backdrop blur on cards, 3D tilt, endless gradient animations) to stay smooth and avoid flicker
- `prefers-reduced-motion` turns animations off

## 🚧 Error pages

Every HTTP error is rendered by `templates/error.html` from a single handler in `app.py` (`ERROR_PAGES` holds the titles and messages). Requests to `/passkey/*`, `/check-username` and JSON requests get a JSON `{"error": "..."}` response instead of HTML. To customize a message or add a status code, edit `ERROR_PAGES`.

## 📄 License

For educational and demonstration purposes.
