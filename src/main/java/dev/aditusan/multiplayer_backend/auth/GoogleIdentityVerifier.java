package dev.aditusan.multiplayer_backend.auth;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;

@Component
public final class GoogleIdentityVerifier {

    private static final GsonFactory JSON = GsonFactory.getDefaultInstance();
    private final GoogleIdTokenVerifier verifier;

    public GoogleIdentityVerifier(
            @Value("${GOOGLE_WEB_CLIENT_ID}") String clientId) {
        if (clientId.isBlank()) {
            throw new IllegalStateException("GOOGLE_WEB_CLIENT_ID is empty");
        }

        this.verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), JSON)
                .setAudience(List.of(clientId))
                .build();
    }

    public VerifiedIdentity verifyIdentity(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            throw invalidToken();
        }

        GoogleIdToken token;
        try {
            token = GoogleIdToken.parse(JSON, rawToken);
        } catch (IOException | IllegalArgumentException e) {
            throw invalidToken();
        }

        try {
            if (!verifier.verify(token)) {
                throw invalidToken();
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new ResponseStatusException(
                    HttpStatus.SERVICE_UNAVAILABLE, "Google token verification unavailable");
        }

        String subject = token.getPayload().getSubject();
        if (subject == null || subject.isBlank()) {
            throw invalidToken();
        }
        String email = token.getPayload().getEmail();

        if (email != null) {
            email = email.strip();

            if (email.isEmpty() || email.length() > 320) {
                email = null;
            }
        }

        boolean verified = email != null
                && Boolean.TRUE.equals(
                        token.getPayload().getEmailVerified());

        return new VerifiedIdentity(subject, email, verified);
    }

    private static ResponseStatusException invalidToken() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid Google ID token");
    }

    public record VerifiedIdentity(
        String subject,
        String email,
        boolean emailVerified) {}

    public String verifyAndGetSubject(String rawToken) {
            return verifyIdentity(rawToken).subject();
    }
}