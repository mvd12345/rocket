package com.example.myapp.Tests;

/**
 * Class B:
 *  - Helper/base class for key generation and component maintenance.
 *  - Contains nested PrivateKey / PublicKey classes.
 *  - Some fields are annotated as @Taint.Trigger (secret),
 *    some as @Taint.UnTrigger (explicitly untainted),
 *    others left without tags (non-secret).
 */
class B {

    /**
     * Public wrapper for key pair.
     */
    public static final class KeyPair {
        private final PrivateKey privateKey;
        private final PublicKey publicKey;

        public KeyPair(PrivateKey privateKey, PublicKey publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public PublicKey getPublicKey() {
            return publicKey;
        }
    }

    public static final class PrivateKey {

        // ===== SECRET COMPONENTS =====

        private final int privateExponent;      // Definitely secret

        private final byte[] secretMask;        // Also secret

        private final int keyId;

        private final int maskedIndex;

        public PrivateKey(int privateExponent, byte[] secretMask, int keyId, int maskedIndex) {
            this.privateExponent = privateExponent;
            this.secretMask = secretMask;
            this.keyId = keyId;
            this.maskedIndex = maskedIndex;
        }

        public int getPrivateExponent() {
            return privateExponent;
        }

        public byte[] getSecretMask() {
            return secretMask;
        }

        public int getKeyId() {
            return keyId;
        }

        public int getMaskedIndex() {
            return maskedIndex;
        }
    }

    public static final class PublicKey {
        private final int modulus;
        private final int publicExponent;
        private final int userIdHash;

        public PublicKey(int modulus, int publicExponent, int userIdHash) {
            this.modulus = modulus;
            this.publicExponent = publicExponent;
            this.userIdHash = userIdHash;
        }

        public int getModulus() {
            return modulus;
        }

        public int getPublicExponent() {
            return publicExponent;
        }

        public int getUserIdHash() {
            return userIdHash;
        }
    }


    public static KeyPair generateKeyPair(String userId) {
        int base = userId.hashCode();

        // Secret components:
        int privateExponent = mix(base, 0xA5A5A5A5);
        byte[] secretMask = new byte[] {
                (byte) (base & 0xFF),
                (byte) ((base >>> 8) & 0xFF),
                (byte) ((base >>> 16) & 0xFF),
                (byte) ((base >>> 24) & 0xFF)
        };

        // Non-secret component:
        int keyId = Math.abs(base);

        int maskedIndex = (privateExponent ^ 0x5A5A5A5A) & 0xFF;

        PrivateKey sk = new PrivateKey(privateExponent, secretMask, keyId, maskedIndex);

        // Public key: non-secret values
        int modulus = Math.abs(mix(base, 0xDEADBEEF)) | 1;
        int publicExponent = 65537;
        int userIdHash = base;

        PublicKey pk = new PublicKey(modulus, publicExponent, userIdHash);

        return new KeyPair(sk, pk);
    }

    private static int mix(int x, int c) {
        int z = x ^ c;
        z ^= (z >>> 13);
        z *= 0x5bd1e995;
        z ^= (z >>> 15);
        return z;
    }
}
