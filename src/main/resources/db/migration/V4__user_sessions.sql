CREATE TABLE user_sessions (
    id UUID PRIMARY KEY,
    username VARCHAR(320) NOT NULL,
    device_id TEXT,
    access_token TEXT NOT NULL,
    refresh_token TEXT NOT NULL UNIQUE,
    access_token_expiry TIMESTAMPTZ NOT NULL,
    refresh_token_expiry TIMESTAMPTZ NOT NULL,
    status VARCHAR(16) NOT NULL CHECK (status IN ('ACTIVE', 'USED', 'REVOKED'))
);
REVOKE DELETE ON user_sessions FROM translations_app;
GRANT SELECT, INSERT, UPDATE ON user_sessions TO translations_app;
