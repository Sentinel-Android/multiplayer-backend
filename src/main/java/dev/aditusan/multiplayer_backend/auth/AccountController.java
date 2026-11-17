package dev.aditusan.multiplayer_backend.auth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1")
public class AccountController {

    private static final Duration SESSION_LIFETIME = Duration.ofMinutes(15);

    private final GoogleIdentityVerifier google;
    private final JdbcClient db;
    private final JwtEncoder encoder;

    public AccountController(
            GoogleIdentityVerifier google, JdbcClient db, JwtEncoder encoder) {
        this.google = google;
        this.db = db;
        this.encoder = encoder;
    }

    @PostMapping("/accounts")
    @ResponseStatus(HttpStatus.CREATED)
    public SessionResponse create(@RequestBody GoogleRequest request) {
        String subject = google.verifyAndGetSubject(request.idToken());

        User user = db.sql("""
                INSERT INTO users (id, google_sub)
                VALUES (:id, :subject)
                ON CONFLICT (google_sub) DO NOTHING
                RETURNING id, score
                """)
                .param("id", UUID.randomUUID())
                .param("subject", subject)
                .query(AccountController::readUser)
                .optional()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.CONFLICT, "Account already exists"));

        return newSession(user);
    }

    @PostMapping("/auth/google")
    public SessionResponse signIn(@RequestBody GoogleRequest request) {
        String subject = google.verifyAndGetSubject(request.idToken());

        User user = db.sql("SELECT id, score FROM users WHERE google_sub = :subject")
                .param("subject", subject)
                .query(AccountController::readUser)
                .optional()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Account not found"));

        return newSession(user);
    }

    @GetMapping("/me")
    public User me(@AuthenticationPrincipal Jwt session) {
        return db.sql("SELECT id, score FROM users WHERE id = :id")
                .param("id", UUID.fromString(session.getSubject()))
                .query(AccountController::readUser)
                .optional()
                .orElseThrow(AccountController::noAccount);
    }

    @DeleteMapping("/me")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@AuthenticationPrincipal Jwt session) {
        int rows = db.sql("DELETE FROM users WHERE id = :id")
                .param("id", UUID.fromString(session.getSubject()))
                .update();

        if (rows == 0) {
            throw noAccount();
        }
    }

    private SessionResponse newSession(User user) {
        Instant now = Instant.now();
        var claims = JwtClaimsSet.builder()
                .issuer(SessionSecurityConfig.ISSUER)
                .subject(user.id().toString())
                .issuedAt(now)
                .expiresAt(now.plus(SESSION_LIFETIME))
                .build();

        var header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims))
                .getTokenValue();

        return new SessionResponse(token, SESSION_LIFETIME.toSeconds(), user);
    }

    private static User readUser(ResultSet row, int rowNumber) throws SQLException {
        return new User(row.getObject("id", UUID.class), row.getInt("score"));
    }

    private static ResponseStatusException noAccount() {
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, "Account no longer exists");
    }

    public record GoogleRequest(String idToken) {}
    public record User(UUID id, int score) {}
    public record SessionResponse(String accessToken, long expiresIn, User user) {}
}