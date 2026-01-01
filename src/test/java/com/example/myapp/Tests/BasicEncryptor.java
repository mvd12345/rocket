package com.example.myapp.Tests;

import java.util.Arrays;

/**
 * Very basic XOR-style “encryption” just to exercise:
 *  - secret/public usage
 *  - random usage in both encrypt/decrypt
 *  - branches that depend on fields
 *  - memory accesses indexed by field-derived values
 */
public class BasicEncryptor {

    /** Derive a byte for keystream using secret-ish fields + random. */
    private static int secretMix(Parameters p, int i) {
        // Branch on secret_length/random_seed to vary flow
        int base = (p.secret_length % 2 == 0) ? 13 : 29;
        base ^= (p.random_seed & 0xFF);

        // Memory access via index tainted by secret_length/random
        int idx = (p.secret_length + i + (p.random[i % p.random.length] & 0xFF)) & 0xFF;
        int table = p.lookup[idx]; // <-- indexed load

        int k = (p.secret_key[i % p.secret_key.length] & 0xFF)
                ^ (p.random[(i * 3 + p.random_seed) % p.random.length] & 0xFF)
                ^ table
                ^ base;
        return k & 0xFF;
    }

    /** Derive a byte for keystream using public-ish fields + random. */
    private static int publicMix(Parameters p, int i) {
        // Branch on pub_len/random_seed to vary flow
        int base = (p.pub_len > 24) ? 0xA5 : 0x3C;
        base ^= ((p.random_seed * 7) & 0xFF);

        // Memory access via index tainted by pub_len/random
        int idx = (p.pub_len + i + (p.random[(i * 2 + 1) % p.random.length] & 0xFF)) & 0xFF;
        int table = p.lookup[idx]; // <-- indexed load

        int k = (p.public_key[(i + p.random_seed) % p.public_key.length] & 0xFF)
                ^ (p.random[(i * 5 + 1) % p.random.length] & 0xFF)
                ^ table
                ^ base;
        return k & 0xFF;
    }

    /** Encrypt uses secret fields + random. */
    public static byte[] encrypt(byte[] plaintext, Parameters p) {
        byte[] out = Arrays.copyOf(plaintext, plaintext.length);
        for (int i = 0; i < out.length; i++) {
            // Another branch to force secret-dependent control flow
            if (((p.secret_key[i % p.secret_key.length] ^ p.random_seed) & 1) == 0) {
                out[i] ^= secretMix(p, i);
            } else {
                // alternate path touches table again to vary behavior
                int idx2 = (p.random_seed + i + (p.random[i % p.random.length] & 0xFF)) & 0xFF;
                out[i] ^= (secretMix(p, i) ^ (p.lookup[idx2] & 0xFF));
            }
        }
        return out;
    }

    /** Decrypt uses public fields + random (symmetric XOR). */
    public static byte[] decrypt(byte[] ciphertext, Parameters p) {
        byte[] out = Arrays.copyOf(ciphertext, ciphertext.length);
        for (int i = 0; i < out.length; i++) {
            // branch on pub_len to alter flow
            if ((p.pub_len + p.random_seed + i) % 3 == 0) {
                out[i] ^= publicMix(p, i);
            } else {
                int idx2 = (p.pub_len + i + (p.random[(i + 3) % p.random.length] & 0xFF)) & 0xFF;
                out[i] ^= (publicMix(p, i) ^ (p.lookup[idx2] & 0xFF));
            }
        }
        return out;
    }

    // Tiny demo runner (optional)
    public static void main(String[] args) {
        Parameters p = new Parameters(
                new byte[]{1,2,3,4,5,6,7,8}, 8,
                new byte[]{9,10,11,12,13,14,15,16}, 8,
                new byte[]{(byte)0xAA, (byte)0xBB, (byte)0xCC, (byte)0xDD}, 7
        );

        byte[] msg = "hello world".getBytes();
        byte[] enc = encrypt(msg, p);
        byte[] dec = decrypt(enc, p);

        System.out.println("match=" + Arrays.equals(msg, dec));
    }
}
