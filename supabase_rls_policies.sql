-- Supabase Row-Level Security (RLS) Policies
-- This script implements RLS policies for the users and passkeys tables

-- Step 1:-- Create tables if they don't exist
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    totp_secret VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS passkeys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    sign_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Enable Row Level Security for users and passkeys tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkeys ENABLE ROW LEVEL SECURITY;

-- Step 2: Create policies for the users table

-- Step 4: Create a function to get the current user ID from the app
-- This helps bridge the gap between your Flask app and PostgreSQL RLS

CREATE OR REPLACE FUNCTION get_session_user_id()
RETURNS INTEGER AS $$
BEGIN
    -- This will be set by your application when making database calls
    RETURN current_setting('app.current_user_id', TRUE)::INTEGER;
EXCEPTION
    WHEN OTHERS THEN
        RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Policy: Users can only view their own data
CREATE POLICY users_select_policy ON users
    FOR SELECT
    USING (id = get_session_user_id() OR get_session_user_id() IS NULL);

-- Policy: Users can only update their own data
CREATE POLICY users_update_policy ON users
    FOR UPDATE
    USING (id = get_session_user_id());

-- Policy: Users cannot delete their own accounts (admin only operation)
-- If you need user deletion, create a separate endpoint with proper authorization

-- Policy: Allow admin access for certain operations
CREATE POLICY users_admin_policy ON users
    FOR ALL
    USING (current_setting('app.is_admin', TRUE)::BOOLEAN = TRUE);

-- Step 3: Create policies for the passkeys table

-- Policy: Users can only view their own passkeys
CREATE POLICY passkeys_select_policy ON passkeys
    FOR SELECT
    USING (user_id = get_session_user_id() OR get_session_user_id() IS NULL);

-- Policy: Users can only insert their own passkeys
CREATE POLICY passkeys_insert_policy ON passkeys
    FOR INSERT
    WITH CHECK (user_id = get_session_user_id());

-- Policy: Users can only update their own passkeys
CREATE POLICY passkeys_update_policy ON passkeys
    FOR UPDATE
    USING (user_id = get_session_user_id());

-- Policy: Users can only delete their own passkeys
CREATE POLICY passkeys_delete_policy ON passkeys
    FOR DELETE
    USING (user_id = get_session_user_id());

-- Policy: Allow admin access for certain operations
CREATE POLICY passkeys_admin_policy ON passkeys
    FOR ALL
    USING (current_setting('app.is_admin', TRUE)::BOOLEAN = TRUE);

-- Step 4: Additional settings for admin access

-- Create a function to check if the current connection has admin privileges
CREATE OR REPLACE FUNCTION is_admin()
RETURNS BOOLEAN AS $$
BEGIN
    RETURN current_setting('app.is_admin', TRUE)::BOOLEAN;
EXCEPTION
    WHEN OTHERS THEN
        RETURN FALSE;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Step 5: Instructions for application integration

/*
To use these RLS policies in your Flask application:

1. When connecting to the database, set the current user ID:
   
   EXECUTE 'SET app.current_user_id = ' || user_id;
   
2. For admin operations, set the admin flag:
   
   EXECUTE 'SET app.is_admin = true';
   
3. Reset after operations:
   
   EXECUTE 'RESET app.current_user_id';
    EXECUTE 'RESET app.is_admin';
*/

-- Step 6: Add instructions for setting the user ID in your application
COMMENT ON FUNCTION get_session_user_id() IS 'Set the user ID with: SET app.current_user_id = <user_id>';
COMMENT ON FUNCTION is_admin() IS 'Set admin mode with: SET app.is_admin = true';