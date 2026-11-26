package dev.aditusan.multiplayer_backend.billing;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableScheduling
public class BillingConfiguration {
    @Bean
    @Order(1)
    SecurityFilterChain playNotificationSecurity(HttpSecurity http, BillingSettings settings) throws Exception {
        http.securityMatcher("/api/v1/billing/notifications")
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        if (!settings.pushEnabled()) {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().denyAll()).build();
        }
        var decoder = NimbusJwtDecoder.withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs").build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer("https://accounts.google.com"), pushClaims(settings)));
        return http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.decoder(decoder))).build();
    }
    static OAuth2TokenValidator<Jwt> pushClaims(BillingSettings settings) {
        return jwt -> {
            if (jwt.getAudience().contains(settings.pushAudience())
                    && settings.pushEmail().equals(jwt.getClaimAsString("email"))
                    && Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified")))
                return OAuth2TokenValidatorResult.success();
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token"));
        };
    }
}