package dev.aditusan.multiplayer_backend.auth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
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
        var identity = google.verifyIdentity(request.idToken());

        User user = db.sql("""
                INSERT INTO users (id, google_sub, email, email_verified)
                VALUES (:id, :subject, :email, :emailVerified)
                ON CONFLICT (google_sub) DO NOTHING
                RETURNING id, score, first_name, last_name, date_of_birth, gender
                """)
                .param("id", UUID.randomUUID())
                .param("subject", identity.subject())
                .param("email", identity.email())
                .param("emailVerified", identity.emailVerified())
                .query(AccountController::readUser)
                .optional()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.CONFLICT, "Account already exists"));

        return newSession(user);
    }

    @PostMapping("/auth/google")
    public SessionResponse signIn(@RequestBody GoogleRequest request) {
        var identity = google.verifyIdentity(request.idToken());

        User user = db.sql("""
                UPDATE users
                SET email = :email,
                    email_verified = :emailVerified
                WHERE google_sub = :subject
                RETURNING id, score, first_name, last_name,
                        date_of_birth, gender
                """)
                .param("subject", identity.subject())
                .param("email", identity.email())
                .param("emailVerified", identity.emailVerified())
                .query(AccountController::readUser)
                .optional()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.NOT_FOUND, "Account not found"));

        return newSession(user);
    }

    @PostMapping("/accounts/profile")
    @ResponseStatus(HttpStatus.CREATED)
    public SessionResponse createProfile(@RequestBody ProfileRequest request) {
        if (request == null) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Profile is required");
        }

        var identity = google.verifyIdentity(request.idToken());
        String subject = identity.subject();

        String firstName = requireName(request.firstName(), "First name");
        String lastName = requireName(request.lastName(), "Last name");
        LocalDate birthday = request.dateOfBirth();

        Gender gender = request.gender() == null
                ? Gender.PREFER_NOT_TO_SAY
                : request.gender();

        if (birthday != null
                && (birthday.isBefore(LocalDate.of(1900, 1, 1))
                || birthday.isAfter(LocalDate.now(ZoneOffset.UTC)))) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST, "Invalid date of birth");
        }

        User user = db.sql("""
                INSERT INTO users (
                    id, google_sub, first_name, last_name,
                    date_of_birth, gender, email, email_verified
                )
                VALUES (
                    :id, :subject, :firstName, :lastName,
                    :birthday, :gender, :email, :emailVerified
                )
                ON CONFLICT (google_sub) DO NOTHING
                RETURNING id, score, first_name, last_name,
                        date_of_birth, gender
                """)
                .param("id", UUID.randomUUID())
                .param("subject", subject)
                .param("firstName", firstName)
                .param("lastName", lastName)
                .param("birthday", birthday)
                .param("gender", gender.name())
                .param("email", identity.email())
                .param("emailVerified", identity.emailVerified())
                .query(AccountController::readUser)
                .optional()
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.CONFLICT, "Account already exists"));

        return newSession(user);
    }

    private static String requireName(String value, String field) {
        String name = value == null ? "" : value.strip();

        if (name.isBlank() || name.codePointCount(0, name.length()) > 100) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    field + " must contain 1–100 characters");
        }

        return name;
    }

    @GetMapping("/me")
    public User me(@AuthenticationPrincipal Jwt session) {
        return db.sql("SELECT id, score, first_name, last_name, date_of_birth, gender FROM users WHERE id = :id")
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

    private static User readUser(ResultSet row, int rowNumber)
            throws SQLException {

        String gender = row.getString("gender");

        return new User(
                row.getObject("id", UUID.class),
                row.getInt("score"),
                row.getString("first_name"),
                row.getString("last_name"),
                row.getObject("date_of_birth", LocalDate.class),
                gender == null ? null : Gender.valueOf(gender));
    }

    private static ResponseStatusException noAccount() {
        return new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, "Account no longer exists");
    }

    public record GoogleRequest(String idToken) {}
    public record User(
            UUID id,
            int score,
            String firstName,
            String lastName,
            LocalDate dateOfBirth,
            Gender gender) {}

    public record ProfileRequest(
            String idToken,
            String firstName,
            String lastName,
            LocalDate dateOfBirth,
            Gender gender) {}
    public record SessionResponse(String accessToken, long expiresIn, User user) {}

    public enum Gender {
        MALE,
        FEMALE,
        PREFER_NOT_TO_SAY
    }
}