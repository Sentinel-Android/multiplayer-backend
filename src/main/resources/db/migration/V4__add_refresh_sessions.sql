CREATE TABLE auth_refresh_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash CHAR(64) NOT NULL,
    previous_token_hash CHAR(64),
    rotation_id UUID,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX auth_refresh_sessions_user_idx
    ON auth_refresh_sessions(user_id);

CREATE INDEX auth_refresh_sessions_expiry_idx
    ON auth_refresh_sessions(expires_at);