package dev.aditusan.multiplayer_backend.billing;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.ArrayList;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public final class GooglePlayGateway implements PlayPurchaseGateway {
    private static final String BASE = "https://androidpublisher.googleapis.com/androidpublisher/v3";
    private static final Gson JSON = new Gson();
    private final GoogleCredentials credentials;
    private final HttpClient client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5)).followRedirects(HttpClient.Redirect.NEVER).build();

    public GooglePlayGateway(BillingSettings settings,
            @Value("${GOOGLE_PLAY_SERVICE_ACCOUNT_JSON:}") String credentialJson) {
        if (!settings.enabled()) { credentials = null; return; }
        if (credentialJson.isBlank()) throw new IllegalStateException("Google Play credentials are required when billing is enabled");
        try {
            credentials = ServiceAccountCredentials.fromStream(new ByteArrayInputStream(
                    credentialJson.getBytes(StandardCharsets.UTF_8)))
                    .createScoped(List.of("https://www.googleapis.com/auth/androidpublisher"));
        } catch (IOException | IllegalArgumentException e) {
            // Never include JSON, private keys or token-bearing URLs in errors.
            throw new IllegalStateException("Invalid Google Play service account credentials");
        }
    }
    @Override public Purchase get(String packageName, String token) {
        return parse(send("GET", "/applications/{package}/purchases/productsv2/tokens/{token}",
                packageName, token));
    }
    @Override public void acknowledge(String packageName, String productId, String token) {
        send("POST", "/applications/{package}/purchases/products/{product}/tokens/{token}:acknowledge",
                packageName, productId, token);
    }
    @Override public List<String> voidedTokens(String packageName) {
        List<String> result = new ArrayList<>();
        String page = "";
        for (int n = 0; n < 100; n++) {
            String json = page.isEmpty()
                    ? send("GET", "/applications/{package}/purchases/voidedpurchases?maxResults=1000", packageName)
                    : send("GET", "/applications/{package}/purchases/voidedpurchases?maxResults=1000&token={page}", packageName, page);
            try {
                Voids response = JSON.fromJson(json, Voids.class);
                if (response == null) throw unavailable();
                if (response.voidedPurchases != null) for (VoidPurchase p : response.voidedPurchases) {
                    BillingService.validateToken(p.purchaseToken);
                    result.add(p.purchaseToken);
                }
                page = response.tokenPagination == null ? null : response.tokenPagination.nextPageToken;
                if (page == null || page.isBlank()) return result;
            } catch (JsonParseException | NullPointerException e) { throw unavailable(); }
        }
        // Never silently truncate a refund scan.
        throw unavailable();
    }
    private String send(String method, String path, Object... values) {
        if (credentials == null) throw unavailable();
        try {
            credentials.refreshIfExpired();
            URI uri = UriComponentsBuilder.fromUriString(BASE + path).encode().buildAndExpand(values).toUri();
            var builder = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(15))
                    .header("Authorization", "Bearer " + credentials.getAccessToken().getTokenValue())
                    .header("Accept", "application/json");
            if (method.equals("POST")) builder.header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString("{}"));
            else builder.GET();
            var response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 404 || response.statusCode() == 410)
                throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY, "Purchase could not be verified");
            if (response.statusCode() < 200 || response.statusCode() >= 300) throw unavailable();
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); throw unavailable();
        } catch (IOException | IllegalArgumentException e) { throw unavailable(); }
    }
    static Purchase parse(String body) {
        try {
            RawPurchase p = JSON.fromJson(body, RawPurchase.class);
            if (p == null || p.purchaseStateContext == null || p.productLineItem == null
                    || p.productLineItem.size() != 1) throw unavailable();
            var items = p.productLineItem.stream().map(line -> {
                Offer o = line.productOfferDetails;
                return new Item(line.productId, o == null ? null : o.purchaseOptionId,
                        o == null ? 0 : o.quantity, o == null ? 0 : o.refundableQuantity,
                        o == null || !"CONSUMPTION_STATE_YET_TO_BE_CONSUMED".equals(o.consumptionState),
                        o != null && o.rentOfferDetails != null, o != null && o.preorderOfferDetails != null);
            }).toList();
            return new Purchase(p.purchaseStateContext.purchaseState, p.obfuscatedExternalAccountId,
                    p.testPurchaseContext != null, "ACKNOWLEDGEMENT_STATE_ACKNOWLEDGED".equals(p.acknowledgementState), items);
        } catch (JsonParseException | NullPointerException e) { throw unavailable(); }
    }
    private static ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Google Play verification unavailable");
    }
    private record RawPurchase(State purchaseStateContext, String obfuscatedExternalAccountId,
            Object testPurchaseContext, String acknowledgementState, List<Line> productLineItem) {}
    private record State(String purchaseState) {}
    private record Voids(List<VoidPurchase> voidedPurchases, Pagination tokenPagination) {}
    private record VoidPurchase(String purchaseToken) {}
    private record Pagination(String nextPageToken) {}
    private record Line(String productId, Offer productOfferDetails) {}
    private record Offer(String purchaseOptionId, int quantity, int refundableQuantity,
            String consumptionState, Object rentOfferDetails, Object preorderOfferDetails) {}
}