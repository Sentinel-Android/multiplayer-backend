package dev.aditusan.multiplayer_backend.billing;

import java.util.List;

public interface PlayPurchaseGateway {
    Purchase get(String packageName, String token);
    void acknowledge(String packageName, String productId, String token);
    List<String> voidedTokens(String packageName);

    record Purchase(String state, String accountId, boolean testPurchase,
                    boolean acknowledged, List<Item> items) {}
    record Item(String productId, String purchaseOptionId, int quantity,
                int refundableQuantity, boolean consumed, boolean rental, boolean preorder) {}
}