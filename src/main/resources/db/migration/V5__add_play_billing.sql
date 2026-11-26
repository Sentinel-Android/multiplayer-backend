CREATE TABLE billing_products (
    package_name VARCHAR(255) NOT NULL,
    product_id VARCHAR(144) NOT NULL,
    purchase_option_id VARCHAR(63) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (package_name, product_id)
);

-- Each product may grant benefits in multiple apps; only the individual
-- Multiplayer product is offered now. Bundle coverage must be explicit.
CREATE TABLE billing_product_grants (
    package_name VARCHAR(255) NOT NULL,
    product_id VARCHAR(144) NOT NULL,
    target_package VARCHAR(255) NOT NULL,
    feature VARCHAR(64) NOT NULL,
    PRIMARY KEY (package_name, product_id, target_package, feature),
    FOREIGN KEY (package_name, product_id)
        REFERENCES billing_products(package_name, product_id)
);

CREATE TABLE billing_accounts (
    user_id UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    obfuscated_account_id VARCHAR(64) NOT NULL UNIQUE
);

CREATE TABLE billing_purchases (
    token_hash CHAR(64) PRIMARY KEY,
    token_ciphertext TEXT NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    product_id VARCHAR(144) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    obfuscated_account_id VARCHAR(64) NOT NULL,
    state VARCHAR(16) NOT NULL CHECK (state IN ('PENDING', 'PURCHASED', 'REVOKED')),
    acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    test_purchase BOOLEAN NOT NULL,
    checked_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    FOREIGN KEY (package_name, product_id)
        REFERENCES billing_products(package_name, product_id)
);
CREATE INDEX billing_purchases_user_idx ON billing_purchases(user_id);
CREATE INDEX billing_purchases_checked_idx ON billing_purchases(checked_at);

-- Snapshot the granted features. Revoking one purchase never removes grants
-- belonging to an independent individual or future bundle purchase.
CREATE TABLE billing_purchase_grants (
    token_hash CHAR(64) NOT NULL REFERENCES billing_purchases(token_hash) ON DELETE CASCADE,
    target_package VARCHAR(255) NOT NULL,
    feature VARCHAR(64) NOT NULL,
    PRIMARY KEY (token_hash, target_package, feature)
);
CREATE TABLE billing_notifications (
    message_id VARCHAR(256) PRIMARY KEY,
    processed_at TIMESTAMP WITH TIME ZONE NOT NULL
);
CREATE INDEX billing_notifications_processed_idx ON billing_notifications(processed_at);
CREATE TABLE billing_voided_tokens (
    token_hash CHAR(64) PRIMARY KEY,
    package_name VARCHAR(255) NOT NULL,
    observed_at TIMESTAMP WITH TIME ZONE NOT NULL
);

INSERT INTO billing_products(package_name, product_id, purchase_option_id)
VALUES ('dev.aditusan.multiplayer', 'premium_ad_removal', 'standard');
INSERT INTO billing_product_grants(package_name, product_id, target_package, feature)
VALUES ('dev.aditusan.multiplayer', 'premium_ad_removal', 'dev.aditusan.multiplayer', 'ad_free');