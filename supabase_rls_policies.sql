-- Supabase / PostgreSQL Row-Level Security for Secure Login Testing.
-- Safe to run more than once. The app also creates/updates these tables itself on
-- startup, so you only need this file to enable and (re)apply the policies.

-- 1) Tables (same shape the app creates)
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password TEXT,                              -- NULL for Google accounts
    secret TEXT,                                -- TOTP secret
    passkey_enabled BOOLEAN DEFAULT FALSE,
    email TEXT,
    email_verified BOOLEAN DEFAULT FALSE,
    google_sub TEXT,
    auth_provider VARCHAR(10) DEFAULT 'password',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    account_locked_until TIMESTAMP
);

CREATE TABLE IF NOT EXISTS passkeys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS email_codes (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    purpose VARCHAR(20) NOT NULL,
    email TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    attempts INTEGER DEFAULT 0,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL
);

-- 2) Helper functions (the app sets app.current_user_id / app.is_admin per connection)
CREATE OR REPLACE FUNCTION get_session_user_id()
RETURNS INTEGER AS $$
BEGIN
    RETURN current_setting('app.current_user_id', TRUE)::INTEGER;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_setting('app.is_admin', TRUE)::BOOLEAN;
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

COMMENT ON FUNCTION get_session_user_id() IS 'Set with: SET app.current_user_id = <user_id>';
COMMENT ON FUNCTION is_admin() IS 'Set with: SET app.is_admin = true';

-- 3) Enable RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE email_codes ENABLE ROW LEVEL SECURITY;

-- 4) users policies
DROP POLICY IF EXISTS users_select_policy ON users;
CREATE POLICY users_select_policy ON users
    FOR SELECT
    USING (id = get_session_user_id() OR get_session_user_id() IS NULL);

DROP POLICY IF EXISTS users_update_policy ON users;
CREATE POLICY users_update_policy ON users
    FOR UPDATE
    USING (id = get_session_user_id());

-- Inserts and deletes (registration, account deletion) go through admin mode only.
DROP POLICY IF EXISTS users_admin_policy ON users;
CREATE POLICY users_admin_policy ON users
    FOR ALL
    USING (is_admin());

-- 5) passkeys policies
DROP POLICY IF EXISTS passkeys_select_policy ON passkeys;
CREATE POLICY passkeys_select_policy ON passkeys
    FOR SELECT
    USING (user_id = get_session_user_id() OR get_session_user_id() IS NULL);

DROP POLICY IF EXISTS passkeys_insert_policy ON passkeys;
CREATE POLICY passkeys_insert_policy ON passkeys
    FOR INSERT
    WITH CHECK (user_id = get_session_user_id());

DROP POLICY IF EXISTS passkeys_update_policy ON passkeys;
CREATE POLICY passkeys_update_policy ON passkeys
    FOR UPDATE
    USING (user_id = get_session_user_id());

DROP POLICY IF EXISTS passkeys_delete_policy ON passkeys;
CREATE POLICY passkeys_delete_policy ON passkeys
    FOR DELETE
    USING (user_id = get_session_user_id());

DROP POLICY IF EXISTS passkeys_admin_policy ON passkeys;
CREATE POLICY passkeys_admin_policy ON passkeys
    FOR ALL
    USING (is_admin());

-- 6) email_codes: only the server (admin mode) can touch one-time codes
DROP POLICY IF EXISTS email_codes_admin_policy ON email_codes;
CREATE POLICY email_codes_admin_policy ON email_codes
    FOR ALL
    USING (is_admin());
