package com.example.myapp.Tests;

import java.util.Arrays;


public class A {

    private final B.KeyPair keyPair;

    public A(B.KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public byte[] encrypt(byte[] plaintext) {
        byte[] ciphertext = new byte[plaintext.length];

        int secretExponent = keyPair.getPrivateKey().getPrivateExponent();       // @Taint.Trigger
        int maskedIndex    = keyPair.getPrivateKey().getMaskedIndex();          // @Taint.UnTrigger
        int userIdHash     = keyPair.getPublicKey().getUserIdHash();            // non-secret public component

        for (int i = 0; i < plaintext.length; i++) {
            if ((secretExponent & 1) == 0) {
                ciphertext[i] = (byte) (plaintext[i] ^ deriveKeyByte(secretExponent, i));
            } else {
                ciphertext[i] = (byte) (plaintext[i] ^ deriveKeyByte(secretExponent * 3, i));
            }

            if (maskedIndex % 2 == 0) {
                ciphertext[i] ^= (byte) (userIdHash & 0x0F);
            } else {
                ciphertext[i] ^= (byte) ((userIdHash >>> 4) & 0x0F);
            }
        }

        return ciphertext;
    }

    public byte[] decrypt(byte[] ciphertext) {
        // XOR-based “encryption” is symmetric
        return encrypt(ciphertext);
    }

    private byte deriveKeyByte(int core, int round) {
        int mixed = core ^ (round * 0x9E3779B9);
        return (byte) (mixed & 0xFF);
    }

    public static void main(String[] args) {
        // Generate key pair via helper class B
        B.KeyPair kp = B.generateKeyPair("user-123");

        // Build encryptor (Class A)
        A encryptor = new A(kp);

        // Build user-level manager (Class C) to drive some scenarios
        C userManager = new C(encryptor, kp);

        byte[] plaintext = "Hello, Taint!".getBytes();
        byte[] ciphertext = userManager.userEncrypt(plaintext);
        byte[] decrypted  = userManager.userDecrypt(ciphertext);

        System.out.println("Plaintext : " + new String(plaintext));
        System.out.println("Ciphertext: " + Arrays.toString(ciphertext));
        System.out.println("Decrypted : " + new String(decrypted));
    }
}
