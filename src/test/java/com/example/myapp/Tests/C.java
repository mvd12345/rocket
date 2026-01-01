package com.example.myapp.Tests;

import java.util.Arrays;

/**
 * Class C (optional, user-level management):
 *  - Uses components from Class A and Class B.
 *  - Performs additional vulnerable branching that your tool should see
 *    across multiple call levels.
 */
class C {

    private final A encryptor;
    private final B.KeyPair keyPair;

    public C(A encryptor, B.KeyPair keyPair) {
        this.encryptor = encryptor;
        this.keyPair = keyPair;
    }

    /**
     * User-level encryption that adds another layer of branching.
     * This introduces:
     *  - A branch on a secret (privateExponent) -> should remain vulnerable.
     *  - A branch on maskedIndex (annotated @Taint.UnTrigger) -> should be cleaned.
     */
    public byte[] userEncrypt(byte[] plaintext) {
        int privateExponent = keyPair.getPrivateKey().getPrivateExponent();  // tainted
        int maskedIndex    = keyPair.getPrivateKey().getMaskedIndex();       // untainted

        byte[] preProcessed;

        // ===== secret-dependent branch (should be flagged) =====
        if (privateExponent > 0) {
            preProcessed = Arrays.copyOf(plaintext, plaintext.length);
        } else {
            // Artificially different code path
            preProcessed = reverse(plaintext);
        }

        // ===== untainted branch (should NOT be flagged after annotation untaint) =====
        if (maskedIndex % 3 == 0) {
            for (int i = 0; i < preProcessed.length; i++) {
                preProcessed[i] ^= 0x0F;
            }
        } else {
            for (int i = 0; i < preProcessed.length; i++) {
                preProcessed[i] ^= 0xF0;
            }
        }

        return encryptor.encrypt(preProcessed);
    }

    public byte[] userDecrypt(byte[] ciphertext) {
        byte[] decrypted = encryptor.decrypt(ciphertext);

        // For completeness, use privateExponent in another branch here too.
        int privateExponent = keyPair.getPrivateKey().getPrivateExponent();  // tainted

        if ((privateExponent & 0xF) == 0) {
            // Branch that would be secret-dependent
            return decrypted;
        } else {
            // Slightly different path
            return Arrays.copyOf(decrypted, decrypted.length);
        }
    }

    private byte[] reverse(byte[] in) {
        byte[] out = new byte[in.length];
        for (int i = 0; i < in.length; i++) {
            out[i] = in[in.length - 1 - i];
        }
        return out;
    }
}
