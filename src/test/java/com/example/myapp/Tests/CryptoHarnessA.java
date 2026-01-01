package com.example.myapp.Tests;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public final class CryptoHarnessA {

    @Taint.Trigger
    public static final byte[] MASTER_KEY = new byte[]{0x01, 0x23, 0x45, 0x67};

    @Taint.Untrigger
    public static final String PUBLIC_CONTEXT = "A/demo";

    private CryptoHarnessA() {}

    @Taint.funTrigger(params = {
            @Taint.Parameters(
                    type = "byte[]",
                    value = "plaintext",
                    index = 0
            )
    })
    public static byte[] xorEncrypt(byte[] plaintext, byte[] salt) {
        byte[] combinedKey = new byte[MASTER_KEY.length + salt.length];
        System.arraycopy(MASTER_KEY, 0, combinedKey, 0, MASTER_KEY.length);
        System.arraycopy(salt, 0, combinedKey, MASTER_KEY.length, salt.length);

        byte[] out = Arrays.copyOf(plaintext, plaintext.length);
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) (out[i] ^ combinedKey[i % combinedKey.length]);
        }
        return out;
    }

    @Taint.funUntrigger
    public static byte[] derivePublicDigest(byte[] publicBlob) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(PUBLIC_CONTEXT.getBytes());
            return md.digest(publicBlob);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Missing SHA-256", e);
        }
    }
}
