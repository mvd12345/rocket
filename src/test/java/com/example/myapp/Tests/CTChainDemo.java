package com.example.myapp.Tests;

import java.math.BigInteger;
import java.util.Arrays;
import java.security.SecureRandom;

public class CTChainDemo {

    // ---------------------------
    // Class attributes (fields)
    // ---------------------------

    // Looks harmless/public, but marking as Trigger means: treat usages as tainted.
    @Taint.Trigger
    public static String PUBLIC_API_KEY = "demo-public-key";

    // Another seemingly public value—mark it as Trigger, too.
    @Taint.Trigger
    public static byte[] PUBLIC_SALT = new byte[]{1,2,3,4,5,6,7,8};

    // Seemingly public config, but we still mark it as Untrigger to override trigger heuristics.
    @Taint.Untrigger
    public static int PUBLIC_WINDOW_SIZE = 64;

    // Another public-looking value annotated with Untrigger.
    @Taint.Untrigger
    public static String PUBLIC_LOG_CHANNEL = "events";

    private static final SecureRandom RNG = new SecureRandom();
    // Large fixed modulus to keep modPow deterministic and quick enough
    private static final BigInteger MODULUS =
            BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));

    /**
     * ENTRY POINT for Robusta.
     * - SECRET-DEPENDENT CONTROL FLOW
     * - then chains into (b) & (c)
     *
     * Mark this method as a TRIGGER site.
     */
    @Taint.funTrigger(params = {
            @Taint.Parameters(
                    type = "byte[]",
                    value = "secret",
                    index = 0
            )
    })
    public static boolean branchOnSecret(byte[] secret) {
        int acc = 0;

        // (a) SECRET-DEPENDENT CONTROL FLOW
        int bit = secret[0] & 1;   // tainted
        if (bit == 0) {
            acc += 1;
        } else {
            acc += 2;
        }

        // Mix in some “public” fields to exercise field annotations
        if (PUBLIC_API_KEY.length() > 0) {
            acc += PUBLIC_WINDOW_SIZE; // Untrigger-annotated field
        }

        // Chain to the next stages (b) and (c)
        acc += lookupBySecretIndex(secret);

        return acc == 0;
    }

    /**
     * (b) SECRET-DEPENDENT MEMORY ACCESS
     * Annotated as UNTRIGGER to show your scanner can pull (source,sink) mappings.
     */
    @Taint.funUntrigger
    private static int lookupBySecretIndex(byte[] secret) {
        int[] table = new int[256];
        for (int i = 0; i < table.length; i++) table[i] = i * i;

        int idx = secret[1] & 0xFF;      // tainted index
        int val = table[idx];            // ArrayRef with tainted index

        // Use another “public” field just to ensure field paths are visited
        if (PUBLIC_LOG_CHANNEL != null && !PUBLIC_LOG_CHANNEL.isEmpty()) {
            val ^= PUBLIC_LOG_CHANNEL.length();
        }

        // Continue the chain: (c) secret-dependent arithmetic + vulnerable call
        val += bigIntModPowWithSecretExp(secret);
        return Taint.taint(val);
    }

    /**
     * (c) SECRET-DEPENDENT ARITHMETIC
     * Also annotated as UNTRIGGER to exercise your reader on another method.
     */
    @Taint.funUntrigger
    private static int bigIntModPowWithSecretExp(byte[] secret) {
        int acc = 0;

        // (c1) SECRET-DEPENDENT ARITHMETIC using '%'
        int publicVal      = 123_456_789;
        int secretDivisor  = (secret[2] & 0xFF) | 1; // ensure non-zero, tainted RHS
        int secretDividend = ((secret[3] & 0xFF) << 8) | (secret[4] & 0xFF); // tainted LHS

        acc += publicVal % Taint.untaint(secretDivisor); // `%` with tainted RHS
        acc += secretDividend % 97;                      // `%` with tainted LHS

        BigInteger base = new BigInteger(1, Arrays.copyOfRange(secret, 5, Math.min(secret.length, 21)));
        if (base.signum() == 0) base = BigInteger.valueOf(2);
        BigInteger exp  = new BigInteger(1, secret);     // tainted exponent

        // Mix in Trigger-annotated field to ensure it’s exercised
        if (PUBLIC_SALT.length > 0) {
            base = base.add(new BigInteger(1, PUBLIC_SALT));
        }

        // BigInteger.modPow with tainted 'exp'
        acc += base.modPow(exp, MODULUS).intValue();

        return acc;
    }

    // Convenience runner
    public static void main(String[] args) {
        byte[] secret = new byte[32];
        RNG.nextBytes(secret);
        boolean res = branchOnSecret(secret);
        System.out.println("res=" + res);
    }
}
