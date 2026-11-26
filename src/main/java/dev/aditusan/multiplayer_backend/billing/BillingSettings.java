package dev.aditusan.multiplayer_backend.billing;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

@Component
public record BillingSettings(
        @Value("${BILLING_ENABLED:false}") boolean enabled,
        @Value("${BILLING_ALLOW_TEST_PURCHASES:false}") boolean allowTestPurchases,
        @Value("${PLAY_RTDN_AUDIENCE:}") String pushAudience,
        @Value("${PLAY_RTDN_SERVICE_ACCOUNT_EMAIL:}") String pushEmail,
        @Value("${PLAY_RTDN_SUBSCRIPTION:}") String pushSubscription) {
    public void requireEnabled() {
        if (!enabled) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "Purchases are temporarily unavailable");
    }
    public boolean pushEnabled() {
        return enabled && !pushAudience.isBlank() && !pushEmail.isBlank() && !pushSubscription.isBlank();
    }
}