package com.example.myapp.Tests;

import java.math.BigInteger;
import java.security.SecureRandom;

public final class CryptoHarnessC {

    @Taint.Trigger
    public static final BigInteger PRIVATE_EXPONENT = new BigInteger("12345678901234567890");

    @Taint.Untrigger
    public static final BigInteger PUBLIC_MODULUS = new BigInteger("1461501637330902918203684832716283019655932542976"); // 2^160

    private static final SecureRandom RNG = new SecureRandom();

    private CryptoHarnessC() {}

    @Taint.funTrigger(params = {
            @Taint.Parameters(
                    type = "java.math.BigInteger",
                    value = "secretBase",
                    index = 0
            )
    })
    public static BigInteger modularPow(BigInteger secretBase) {
        return secretBase.modPow(PRIVATE_EXPONENT, PUBLIC_MODULUS);
    }

    @Taint.funUntrigger
    public static BigInteger generatePublicPrime(int bits) {
        return BigInteger.probablePrime(bits, RNG);
    }
}
