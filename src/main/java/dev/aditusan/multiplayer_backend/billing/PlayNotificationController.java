package dev.aditusan.multiplayer_backend.billing;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

@RestController
@RequestMapping("/api/v1/billing/notifications")
public class PlayNotificationController {
    private final BillingService billing;
    private final BillingSettings settings;
    public PlayNotificationController(BillingService billing, BillingSettings settings) {
        this.billing = billing; this.settings = settings;
    }
    // Reached only through the separate Google RS256-authenticated filter chain.
    @PostMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void receive(@RequestBody Envelope envelope) {
        if (!settings.pushEnabled()) throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
        if (envelope == null || !settings.pushSubscription().equals(envelope.subscription())
                || envelope.message() == null || envelope.message().data() == null
                || envelope.message().data().length() > 32768) throw invalid();
        String packageName; String token = null; boolean test;
        try {
            JsonObject payload = JsonParser.parseString(new String(Base64.getDecoder()
                    .decode(envelope.message().data()), StandardCharsets.UTF_8)).getAsJsonObject();
            packageName = payload.get("packageName").getAsString();
            test = payload.has("testNotification");
            if (!test) {
                String kind = payload.has("oneTimeProductNotification") ? "oneTimeProductNotification"
                        : payload.has("voidedPurchaseNotification") ? "voidedPurchaseNotification" : null;
                if (kind == null) return; // Subscriptions are not offered by this version.
                token = payload.getAsJsonObject(kind).get("purchaseToken").getAsString();
            }
        } catch (RuntimeException e) { throw invalid(); }
        billing.notification(envelope.message().messageId(), packageName, token, test);
    }
    private static ResponseStatusException invalid() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid Play notification");
    }
    public record Envelope(Message message, String subscription) {}
    public record Message(String data, String messageId) {}
}