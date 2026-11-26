package dev.aditusan.multiplayer_backend.billing;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public final class PurchaseTokenCipher {
    private final byte[] key;
    private final SecureRandom random = new SecureRandom();
    public PurchaseTokenCipher(BillingSettings settings,
            @Value("${BILLING_TOKEN_ENCRYPTION_KEY:}") String encoded) {
        try { key = encoded.isBlank() ? new byte[0] : Base64.getDecoder().decode(encoded); }
        catch (IllegalArgumentException e) { throw new IllegalStateException("Invalid billing encryption key"); }
        if (settings.enabled() && key.length != 32)
            throw new IllegalStateException("BILLING_TOKEN_ENCRYPTION_KEY must decode to 32 bytes");
    }
    public String encrypt(String token) {
        byte[] iv = new byte[12]; random.nextBytes(iv);
        try {
            Cipher cipher = cipher(Cipher.ENCRYPT_MODE, iv);
            byte[] encrypted = cipher.doFinal(token.getBytes(StandardCharsets.UTF_8));
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            return Base64.getEncoder().encodeToString(result);
        } catch (GeneralSecurityException e) { throw new IllegalStateException("Purchase storage unavailable"); }
    }
    public String decrypt(String value) {
        try {
            byte[] bytes = Base64.getDecoder().decode(value);
            if (bytes.length < 28) throw new GeneralSecurityException();
            byte[] iv = java.util.Arrays.copyOfRange(bytes, 0, 12);
            return new String(cipher(Cipher.DECRYPT_MODE, iv).doFinal(bytes, 12, bytes.length - 12),
                    StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException("Purchase storage unavailable");
        }
    }
    private Cipher cipher(int mode, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        cipher.updateAAD("multiplayer-play-purchase-v1".getBytes(StandardCharsets.UTF_8));
        return cipher;
    }
    static String hash(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
}