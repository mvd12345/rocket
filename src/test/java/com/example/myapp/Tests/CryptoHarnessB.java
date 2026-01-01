package com.example.myapp.Tests;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.concurrent.ThreadLocalRandom;

public final class CryptoHarnessB {

    @Taint.Trigger
    public static final byte[] HMAC_KEY = "hmac-key-demo".getBytes(StandardCharsets.UTF_8);

    @Taint.Untrigger
    public static final String PUBLIC_CHANNEL = "metrics/B";

    private CryptoHarnessB() {}

    @Taint.funTrigger(params = {
            @Taint.Parameters(
                    type = "byte[]",
                    value = "payload",
                    index = 1
            )
    })
    public static String generateMac(byte[] seedNonce, byte[] payload) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(HMAC_KEY);
            md.update(seedNonce);
            md.update(payload);
            byte[] digest = md.digest();
            return Base64.getEncoder().encodeToString(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Missing SHA-512", e);
        }
    }

    @Taint.funUntrigger
    public static byte[] issuePublicNonce(byte[] publicInfo) {
        byte[] nonce = new byte[32];
        ThreadLocalRandom.current().nextBytes(nonce);
        for (int i = 0; i < nonce.length && i < publicInfo.length; i++) {
            nonce[i] ^= publicInfo[i];
        }
        return nonce;
    }
}
