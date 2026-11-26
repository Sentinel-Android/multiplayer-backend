package dev.aditusan.multiplayer_backend.billing;

import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/billing")
public class BillingController {
    private final BillingService billing;
    public BillingController(BillingService billing) { this.billing = billing; }
    @GetMapping("/catalog")
    public List<BillingService.CatalogProduct> catalog(@AuthenticationPrincipal Jwt jwt,
            @RequestParam String packageName) {
        return billing.catalog(user(jwt), packageName);
    }
    @PostMapping("/checkout")
    public BillingService.Checkout checkout(@AuthenticationPrincipal Jwt jwt, @RequestBody CheckoutRequest request) {
        if (request == null) throw bad();
        return billing.checkout(user(jwt), request.packageName(), request.productId());
    }
    @PostMapping("/verify")
    public BillingService.Verification verify(@AuthenticationPrincipal Jwt jwt, @RequestBody VerifyRequest request) {
        if (request == null) throw bad();
        return billing.verify(user(jwt), request.packageName(), request.purchaseToken());
    }
    @GetMapping("/entitlements")
    public BillingService.Entitlements entitlements(@AuthenticationPrincipal Jwt jwt,
            @RequestParam String packageName) {
        return billing.entitlements(user(jwt), packageName);
    }
    private static UUID user(Jwt jwt) {
        try { return UUID.fromString(jwt.getSubject()); }
        catch (IllegalArgumentException | NullPointerException e) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid session");
        }
    }
    private static ResponseStatusException bad() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Billing request is required");
    }
    public record CheckoutRequest(String packageName, String productId) {}
    public record VerifyRequest(String packageName, String purchaseToken) {}
}