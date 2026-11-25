package dev.aditusan.multiplayer_backend.auth;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import dev.aditusan.multiplayer_backend.auth.AccountController.SessionResponse;
import dev.aditusan.multiplayer_backend.auth.AccountController.User;

@Service
public class PersistentSessionService {

    static final Duration ACCESS_LIFETIME = Duration.ofMinutes(15);
    static final Duration REFRESH_IDLE_LIFETIME = Duration.ofDays(90);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JdbcClient db;
    private final JwtEncoder encoder;
    private final SecretKey rotationKey;
    private final Clock clock;

    @Autowired
    public PersistentSessionService(
            JdbcClient db,
            JwtEncoder encoder,
            SecretKey signingKey) {
        this(db, encoder, signingKey, Clock.systemUTC());
    }

    PersistentSessionService(
            JdbcClient db,
            JwtEncoder encoder,
            SecretKey signingKey,
            Clock clock) {
        this.db = db;
        this.encoder = encoder;
        this.clock = clock;

        this.rotationKey = new SecretKeySpec(
                hmac(signingKey, "multiplayer-refresh-rotation-key-v1"),
                "HmacSHA256");
    }

    @Transactional
    public SessionResponse start(User user) {
        UUID id = UUID.randomUUID();

        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);

        String token = id + "."
                + Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(bytes);

        Instant expires = clock.instant().plus(REFRESH_IDLE_LIFETIME);

        db.sql("""
                DELETE FROM auth_refresh_sessions
                WHERE user_id = :user AND expires_at <= :now
                """)
                .param("user", user.id())
                .param("now", clock.instant().atOffset(ZoneOffset.UTC))
                .update();

        db.sql("""
                INSERT INTO auth_refresh_sessions (
                    id, user_id, token_hash, expires_at
                )
                VALUES (:id, :user, :hash, :expires)
                """)
                .param("id", id)
                .param("user", user.id())
                .param("hash", hash(token))
                .param("expires", expires.atOffset(ZoneOffset.UTC))
                .update();

        return issue(user, token, expires);
    }

    // Revocation must remain committed when a replay returns HTTP 401.
    @Transactional(noRollbackFor = ResponseStatusException.class)
    public SessionResponse refresh(String rawToken, UUID requestId) {
        UUID id = tokenId(rawToken);

        if (requestId == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Request ID is required");
        }

        Stored stored = db.sql("""
                SELECT s.token_hash, s.previous_token_hash,
                       s.rotation_id, s.expires_at,
                       u.id, u.score, u.first_name, u.last_name,
                       u.date_of_birth, u.gender
                FROM auth_refresh_sessions s
                JOIN users u ON u.id = s.user_id
                WHERE s.id = :id
                FOR UPDATE OF s
                """)
                .param("id", id)
                .query((row, n) -> new Stored(
                        row.getString("token_hash"),
                        row.getString("previous_token_hash"),
                        row.getObject("rotation_id", UUID.class),
                        row.getObject(
                                "expires_at", OffsetDateTime.class)
                                .toInstant(),
                        AccountController.readUser(row, n)))
                .optional()
                .orElseThrow(PersistentSessionService::invalidSession);

        if (!stored.expires().isAfter(clock.instant())) {
            remove(id);
            throw invalidSession();
        }

        String suppliedHash = hash(rawToken);

        if (matches(suppliedHash, stored.currentHash())) {
            String next = rotatedToken(id, rawToken, requestId);
            Instant expires = clock.instant().plus(REFRESH_IDLE_LIFETIME);

            db.sql("""
                    UPDATE auth_refresh_sessions
                    SET token_hash = :next,
                        previous_token_hash = :previous,
                        rotation_id = :request,
                        expires_at = :expires
                    WHERE id = :id
                    """)
                    .param("next", hash(next))
                    .param("previous", suppliedHash)
                    .param("request", requestId)
                    .param("expires", expires.atOffset(ZoneOffset.UTC))
                    .param("id", id)
                    .update();

            return issue(stored.user(), next, expires);
        }

        if (matches(suppliedHash, stored.previousHash())) {
            // Retrying the same request can recover a lost response.
            String next = rotatedToken(id, rawToken, requestId);

            if (requestId.equals(stored.rotationId())
                    && matches(hash(next), stored.currentHash())) {
                return issue(stored.user(), next, stored.expires());
            }

            // Previous credential reused for a different rotation.
            remove(id);
        }

        throw invalidSession();
    }

    @Transactional
    public void logout(String token) {
        UUID id;

        try {
            id = tokenId(token);
        } catch (ResponseStatusException ignored) {
            return;
        }

        String digest = hash(token);

        // Accept the previous credential after an interrupted refresh too.
        db.sql("""
                DELETE FROM auth_refresh_sessions
                WHERE id = :id
                  AND (
                      token_hash = :hash
                      OR previous_token_hash = :hash
                  )
                """)
                .param("id", id)
                .param("hash", digest)
                .update();
    }

    private void remove(UUID id) {
        db.sql("DELETE FROM auth_refresh_sessions WHERE id = :id")
                .param("id", id)
                .update();
    }

    private SessionResponse issue(
            User user,
            String refreshToken,
            Instant refreshExpiry) {
        Instant now = clock.instant();

        var claims = JwtClaimsSet.builder()
                .issuer(SessionSecurityConfig.ISSUER)
                .subject(user.id().toString())
                .issuedAt(now)
                .expiresAt(now.plus(ACCESS_LIFETIME))
                .build();

        var header = JwsHeader.with(MacAlgorithm.HS256).build();

        String access = encoder.encode(
                JwtEncoderParameters.from(header, claims))
                .getTokenValue();

        return new SessionResponse(
                access,
                ACCESS_LIFETIME.toSeconds(),
                user,
                refreshToken,
                Duration.between(now, refreshExpiry).toSeconds());
    }

    private String rotatedToken(
            UUID id,
            String oldToken,
            UUID request) {
        return id + "."
                + Base64.getUrlEncoder()
                        .withoutPadding()
                        .encodeToString(
                                hmac(rotationKey, oldToken + ":" + request));
    }

    private static UUID tokenId(String raw) {
        if (raw == null
                || !raw.matches(
                        "[0-9a-fA-F-]{36}\\.[A-Za-z0-9_-]{43}")) {
            throw invalidSession();
        }

        try {
            return UUID.fromString(raw.substring(0, 36));
        } catch (IllegalArgumentException ignored) {
            throw invalidSession();
        }
    }

    private static boolean matches(String a, String b) {
        return b != null
                && MessageDigest.isEqual(
                        a.getBytes(StandardCharsets.US_ASCII),
                        b.getBytes(StandardCharsets.US_ASCII));
    }

    private static String hash(String token) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] hmac(SecretKey key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(
                    message.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ResponseStatusException invalidSession() {
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED,
                "Session expired or revoked");
    }

    private record Stored(
            String currentHash,
            String previousHash,
            UUID rotationId,
            Instant expires,
            User user) {}
}