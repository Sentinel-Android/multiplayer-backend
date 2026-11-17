ALTER TABLE users
    ADD COLUMN gender VARCHAR(20),
    ADD COLUMN email VARCHAR(320),
    ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

ALTER TABLE users
    ADD CONSTRAINT users_gender_supported
    CHECK (
        gender IS NULL
        OR gender IN ('MALE', 'FEMALE', 'PREFER_NOT_TO_SAY')
    );