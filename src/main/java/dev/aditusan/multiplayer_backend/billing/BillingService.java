package dev.aditusan.multiplayer_backend.billing;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class BillingService {
    private static final Logger LOG = LoggerFactory.getLogger(BillingService.class);
    private final JdbcClient db;
    private final TransactionTemplate tx;
    private final BillingSettings settings;
    private final PlayPurchaseGateway play;
    private final PurchaseTokenCipher cipher;
    private final long recheckSeconds;
    private final SecureRandom random = new SecureRandom();
    private Instant lastVoidsCheck = Instant.EPOCH;

    public BillingService(JdbcClient db, TransactionTemplate tx, BillingSettings settings,
            PlayPurchaseGateway play, PurchaseTokenCipher cipher,
            @Value("${BILLING_RECHECK_SECONDS:21600}") long recheckSeconds) {
        this.db = db; this.tx = tx; this.settings = settings; this.play = play; this.cipher = cipher;
        if (recheckSeconds < 30) throw new IllegalArgumentException("Billing recheck must be at least 30 seconds");
        this.recheckSeconds = recheckSeconds;
    }
    public Checkout checkout(UUID user, String packageName, String productId) {
        settings.requireEnabled(); validateId(packageName, 255); validateId(productId, 144);
        return tx.execute(status -> {
            requireUser(user, true);
            Product product = product(packageName, productId);
            if (!product.enabled) throw bad("Product is unavailable");
            byte[] bytes = new byte[32]; random.nextBytes(bytes);
            String candidate = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
            db.sql("""
                    INSERT INTO billing_accounts(user_id, obfuscated_account_id) VALUES (:user, :account)
                    ON CONFLICT (user_id) DO NOTHING
                    """).param("user", user).param("account", candidate).update();
            String account = db.sql("SELECT obfuscated_account_id FROM billing_accounts WHERE user_id = :user")
                    .param("user", user).query(String.class).single();
            return new Checkout(packageName, productId, product.option, account);
        });
    }
    public Verification verify(UUID user, String packageName, String token) {
        settings.requireEnabled(); requireUser(user, false); validateToken(token); validateId(packageName, 255);
        Stored result = synchronize(packageName, token, user);
        acknowledge(result.hash);
        Stored latest = stored(result.hash, false);
        return new Verification(latest.state, latest.acknowledged, entitlements(user, packageName));
    }
    public Entitlements entitlements(UUID user, String packageName) {
        settings.requireEnabled(); requireUser(user, false); validateId(packageName, 255);
        List<String> features = db.sql("""
                SELECT DISTINCT g.feature FROM billing_purchase_grants g
                JOIN billing_purchases p ON p.token_hash = g.token_hash
                WHERE p.user_id = :user AND p.state = 'PURCHASED' AND g.target_package = :package
                  AND (:allowTests = TRUE OR p.test_purchase = FALSE)
                ORDER BY g.feature
                """).param("user", user).param("package", packageName)
                .param("allowTests", settings.allowTestPurchases()).query(String.class).list();
        return new Entitlements(packageName, features.contains("ad_free"), features);
    }
    public List<CatalogProduct> catalog(UUID user, String packageName) {
        settings.requireEnabled(); requireUser(user, false); validateId(packageName, 255);
        return db.sql("""
                SELECT package_name, product_id, purchase_option_id FROM billing_products
                WHERE package_name = :package AND enabled = TRUE ORDER BY product_id
                """).param("package", packageName).query((row, n) -> new CatalogProduct(
                        row.getString(1), row.getString(2), row.getString(3))).list();
    }

    // A fresh Google result is required for every claim/restore. Its attribution,
    // never a user ID supplied by the client, selects the original recipient.
    Stored synchronize(String packageName, String token, UUID actor) {
        validateToken(token); validateId(packageName, 255);
        if (db.sql("SELECT COUNT(*) FROM billing_products WHERE package_name = :package")
                .param("package", packageName).query(Long.class).single() == 0) throw bad("Unknown app package");
        PlayPurchaseGateway.Purchase purchase = play.get(packageName, token);
        if (purchase == null || purchase.items() == null || purchase.items().size() != 1)
            throw unavailable();
        var item = purchase.items().getFirst();
        Product product = product(packageName, item.productId());
        if (purchase.state() == null || !List.of("PENDING", "PURCHASED", "CANCELLED").contains(purchase.state())) throw unavailable();
        if (purchase.accountId() == null || purchase.accountId().isBlank()) throw forbidden();
        if (purchase.testPurchase() && !settings.allowTestPurchases()) throw bad("Test purchases are disabled");
        if ("PURCHASED".equals(purchase.state()) &&
                (!product.option.equals(item.purchaseOptionId()) || item.quantity() != 1
                || item.consumed() || item.rental() || item.preorder()
                || item.refundableQuantity() < 0 || item.refundableQuantity() > 1))
            throw bad("Unsupported purchase option");
        String hash = PurchaseTokenCipher.hash(token);
        return tx.execute(status -> {
            UUID owner = db.sql("SELECT user_id FROM billing_accounts WHERE obfuscated_account_id = :account")
                    .param("account", purchase.accountId()).query(UUID.class).optional().orElse(null);
            if (owner == null || (actor != null && !owner.equals(actor))) throw forbidden();
            requireUser(owner, true);
            db.sql("""
                    INSERT INTO billing_purchases(token_hash, token_ciphertext, package_name, product_id,
                        user_id, obfuscated_account_id, state, acknowledged, test_purchase, checked_at, created_at)
                    VALUES (:hash, :encrypted, :package, :product, :user, :account, 'PENDING', FALSE, :test, :now, :now)
                    ON CONFLICT (token_hash) DO NOTHING
                    """).param("hash", hash).param("encrypted", cipher.encrypt(token))
                    .param("package", packageName).param("product", item.productId()).param("user", owner)
                    .param("account", purchase.accountId()).param("test", purchase.testPurchase())
                    .param("now", now()).update();
            Stored existing = stored(hash, true);
            if (!owner.equals(existing.user) || !packageName.equals(existing.packageName)
                    || !item.productId().equals(existing.productId)
                    || !constantEquals(existing.account, purchase.accountId())) throw forbidden();
            // Revocation is terminal for this token. A stale success cannot resurrect it.
            String state = existing.state;
            if (isVoided(hash, packageName)) state = "REVOKED";
            if (!state.equals("REVOKED")) {
                if (purchase.state().equals("CANCELLED")
                        || (purchase.state().equals("PURCHASED") && item.refundableQuantity() == 0)) state = "REVOKED";
                else if (purchase.state().equals("PURCHASED")) state = "PURCHASED";
            }
            db.sql("""
                    UPDATE billing_purchases SET state = :state, acknowledged = :ack, checked_at = :now,
                        token_ciphertext = :encrypted
                    WHERE token_hash = :hash
                    """).param("state", state).param("ack", existing.acknowledged || purchase.acknowledged())
                    .param("now", now()).param("hash", hash).param("encrypted", cipher.encrypt(token)).update();
            if (state.equals("PURCHASED") && !existing.state.equals("PURCHASED")) {
                // A snapshot for this purchase; existing grants are never overwritten.
                for (Grant grant : grants(packageName, item.productId())) {
                    db.sql("""
                            INSERT INTO billing_purchase_grants(token_hash, target_package, feature)
                            VALUES (:hash, :package, :feature) ON CONFLICT DO NOTHING
                            """).param("hash", hash).param("package", grant.packageName)
                            .param("feature", grant.feature).update();
                }
            }
            return stored(hash, false);
        });
    }
    private void acknowledge(String hash) {
        // This is a separate transaction, after the verified purchase/grants committed.
        try {
            tx.executeWithoutResult(status -> {
                Stored p = stored(hash, true);
                if (!p.state.equals("PURCHASED") || p.acknowledged || p.user == null) return;
                play.acknowledge(p.packageName, p.productId, token(p));
                db.sql("UPDATE billing_purchases SET acknowledged = TRUE WHERE token_hash = :hash")
                        .param("hash", hash).update();
            });
        } catch (RuntimeException e) {
            // No exception message: upstream exceptions can contain token-bearing URLs.
            LOG.warn("billing.acknowledgement.retry_required");
        }
    }
    public void notification(String messageId, String packageName, String token, boolean test) {
        settings.requireEnabled(); validateId(messageId, 256);
        boolean seen = db.sql("SELECT COUNT(*) FROM billing_notifications WHERE message_id = :id")
                .param("id", messageId).query(Long.class).single() > 0;
        if (seen) return;
        if (!test) {
            validateToken(token); validateId(packageName, 255);
            if (!isVoided(PurchaseTokenCipher.hash(token), packageName)) {
                Stored result = synchronize(packageName, token, null);
                acknowledge(result.hash);
            }
        }
        db.sql("""
                INSERT INTO billing_notifications(message_id, processed_at) VALUES (:id, :now)
                ON CONFLICT (message_id) DO NOTHING
                """).param("id", messageId).param("now", now()).update();
        LOG.info("billing.notification.processed");
    }
    @Scheduled(fixedDelayString = "${BILLING_POLL_INTERVAL_MS:30000}",
            initialDelayString = "${BILLING_POLL_INTERVAL_MS:30000}")
    public void reconcile() {
        if (!settings.enabled()) return;
        if (lastVoidsCheck.isBefore(Instant.now().minusSeconds(3600))) {
            try {
                List<String> packages = db.sql("SELECT DISTINCT package_name FROM billing_products")
                        .query(String.class).list();
                for (String packageName : packages) rememberVoids(packageName, play.voidedTokens(packageName));
                lastVoidsCheck = Instant.now();
            } catch (RuntimeException e) { LOG.warn("billing.voided_scan.retry_required"); }
        }
        List<Stored> rows = db.sql("""
                SELECT * FROM billing_purchases WHERE user_id IS NOT NULL AND state <> 'REVOKED'
                AND (:allowTests = TRUE OR test_purchase = FALSE)
                AND ((acknowledged = FALSE OR state = 'PENDING') AND checked_at < :retry
                    OR checked_at < :recheck)
                ORDER BY checked_at LIMIT 20
                """).param("retry", OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(30))
                .param("recheck", OffsetDateTime.now(ZoneOffset.UTC).minusSeconds(recheckSeconds))
                .param("allowTests", settings.allowTestPurchases())
                .query(BillingService::readStored).list();
        for (Stored p : rows) {
            try {
                Stored result = synchronize(p.packageName, token(p), null);
                acknowledge(result.hash);
            } catch (RuntimeException e) {
                // Retain verified ownership on an outage; move failed work to the back
                // of the bounded queue so other pending purchases are not starved.
                db.sql("UPDATE billing_purchases SET checked_at = :now WHERE token_hash = :hash")
                        .param("now", now()).param("hash", p.hash).update();
                LOG.warn("billing.reconciliation.retry_required");
            }
        }
        db.sql("DELETE FROM billing_notifications WHERE processed_at < :cutoff")
                .param("cutoff", OffsetDateTime.now(ZoneOffset.UTC).minusDays(30)).update();
    }
    private boolean isVoided(String hash, String packageName) {
        return db.sql("SELECT COUNT(*) FROM billing_voided_tokens WHERE token_hash = :hash AND package_name = :package")
                .param("hash", hash).param("package", packageName).query(Long.class).single() > 0;
    }
    private String token(Stored purchase) {
        String token = cipher.decrypt(purchase.encrypted);
        if (!constantEquals(purchase.hash, PurchaseTokenCipher.hash(token)))
            throw new IllegalStateException("Purchase storage integrity check failed");
        return token;
    }
    private void rememberVoids(String packageName, List<String> tokens) {
        tx.executeWithoutResult(status -> {
            for (int offset = 0; offset < tokens.size(); offset += 200) {
                List<String> hashes = tokens.subList(offset, Math.min(tokens.size(), offset + 200))
                        .stream().map(PurchaseTokenCipher::hash).distinct().toList();
                List<String> values = new java.util.ArrayList<>();
                for (int n = 0; n < hashes.size(); n++) values.add("(:hash" + n + ", :package, :now)");
                var insert = db.sql("INSERT INTO billing_voided_tokens(token_hash, package_name, observed_at) VALUES "
                        + String.join(",", values) + " ON CONFLICT (token_hash) DO NOTHING")
                        .param("package", packageName).param("now", now());
                for (int n = 0; n < hashes.size(); n++) insert = insert.param("hash" + n, hashes.get(n));
                insert.update();
                db.sql("UPDATE billing_purchases SET state = 'REVOKED' WHERE package_name = :package AND token_hash IN (:hashes)")
                        .param("package", packageName).param("hashes", hashes).update();
            }
        });
    }
    private Product product(String packageName, String productId) {
        validateId(productId, 144);
        return db.sql("""
                SELECT purchase_option_id, enabled FROM billing_products
                WHERE package_name = :package AND product_id = :product
                """).param("package", packageName).param("product", productId)
                .query((row, n) -> new Product(row.getString(1), row.getBoolean(2)))
                .optional().orElseThrow(() -> bad("Unknown product"));
    }
    private List<Grant> grants(String packageName, String productId) {
        List<Grant> grants = db.sql("""
                SELECT target_package, feature FROM billing_product_grants
                WHERE package_name = :package AND product_id = :product
                """).param("package", packageName).param("product", productId)
                .query((row, n) -> new Grant(row.getString(1), row.getString(2))).list();
        if (grants.isEmpty()) throw unavailable();
        return grants;
    }
    private Stored stored(String hash, boolean lock) {
        return db.sql("SELECT * FROM billing_purchases WHERE token_hash = :hash" + (lock ? " FOR UPDATE" : ""))
                .param("hash", hash).query(BillingService::readStored).single();
    }
    private static Stored readStored(ResultSet row, int number) throws SQLException {
        return new Stored(row.getString("token_hash"), row.getString("token_ciphertext"),
                row.getString("package_name"), row.getString("product_id"), row.getObject("user_id", UUID.class),
                row.getString("obfuscated_account_id"), row.getString("state"), row.getBoolean("acknowledged"));
    }
    private void requireUser(UUID user, boolean lock) {
        if (user == null || db.sql("SELECT id FROM users WHERE id = :user" + (lock ? " FOR UPDATE" : ""))
                .param("user", user).query(UUID.class).optional().isEmpty())
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Account no longer exists");
    }
    static void validateToken(String token) {
        if (token == null || token.isEmpty() || token.length() > 8192
                || !token.chars().allMatch(c -> c >= 33 && c <= 126)) throw bad("Invalid purchase token");
    }
    private static void validateId(String value, int max) {
        if (value == null || value.isBlank() || value.length() > max) throw bad("Invalid billing request");
    }
    private static boolean constantEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
    private static OffsetDateTime now() { return Instant.now().atOffset(ZoneOffset.UTC); }
    private static ResponseStatusException bad(String reason) {
        return new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, reason);
    }
    private static ResponseStatusException forbidden() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Sign in to the account that started this purchase");
    }
    private static ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Purchase activation unavailable");
    }
    private record Product(String option, boolean enabled) {}
    private record Grant(String packageName, String feature) {}
    record Stored(String hash, String encrypted, String packageName, String productId,
                  UUID user, String account, String state, boolean acknowledged) {}
    public record Checkout(String packageName, String productId, String purchaseOptionId, String obfuscatedAccountId) {}
    public record Verification(String state, boolean acknowledged, Entitlements entitlements) {}
    public record Entitlements(String packageName, boolean adFree, List<String> features) {}
    public record CatalogProduct(String packageName, String productId, String purchaseOptionId) {}
}