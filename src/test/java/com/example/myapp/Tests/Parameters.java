package com.example.myapp.Tests;

import java.util.Arrays;
import java.util.Objects;

/** Parameter bag used by the crypto demo. */
public class Parameters {
    // “Secret” side
    @Taint.Trigger
    public byte[] secret_key;     // e.g., 32 bytes
    @Taint.Untrigger
    public int    secret_length;  // e.g., 32 or 16

    // “Public” side
    @Taint.Untrigger
    public byte[] public_key;     // e.g., 32 bytes
    @Taint.Untrigger
    public int    pub_len;        // e.g., 32 or 16

    // Random/nonce-ish material shared by both
    @Taint.Trigger
    public byte[] random;         // e.g., 16 bytes
    @Taint.Trigger
    public int    random_seed;    // e.g., 7

    // A small table to ensure memory accesses via tainted indices
    @Taint.Untrigger
    public int[] lookup = new int[256];

    public Parameters(byte[] secret_key,
                      int secret_length,
                      byte[] public_key,
                      int pub_len,
                      byte[] random,
                      int random_seed) {
        this.secret_key     = Objects.requireNonNull(secret_key);
        this.secret_length  = secret_length;
        this.public_key     = Objects.requireNonNull(public_key);
        this.pub_len        = pub_len;
        this.random         = Objects.requireNonNull(random);
        this.random_seed    = random_seed;

        for (int i = 0; i < lookup.length; i++) lookup[i] = (i * 37) ^ 0x5A;
    }

    @Override public String toString() {
        return "Parameters{" +
                "secret_length=" + secret_length +
                ", pub_len=" + pub_len +
                ", random_seed=" + random_seed +
                ", secret_key=" + Arrays.toString(Arrays.copyOf(secret_key, Math.min(4, secret_key.length))) + "..." +
                ", public_key=" + Arrays.toString(Arrays.copyOf(public_key, Math.min(4, public_key.length))) + "..." +
                ", random=" + Arrays.toString(Arrays.copyOf(random, Math.min(4, random.length))) + "..." +
                '}';
    }
}
