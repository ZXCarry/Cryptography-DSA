package org.example;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class DSA {
    private final SecureRandom random = new SecureRandom();
    private final MessageDigest digest;

    // Parametry i klucze DSA
    public BigInteger p, q, g, x, y;

    public DSA() {
        try {
            digest = MessageDigest.getInstance("SHA-256");
            generateKeys();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    public void generateKeys() {
        BigInteger q;
        do {
            q = BigInteger.probablePrime(160, random);
        } while (q.bitLength() != 160);

        int targetBitLength = 1024;
        BigInteger k;
        do {
            int kBits = targetBitLength - q.bitLength();
            k = new BigInteger(kBits, random);
            p = q.multiply(k).add(BigInteger.ONE);
        } while (!p.isProbablePrime(40) || p.bitLength() != targetBitLength);

        BigInteger h;
        do {
            h = new BigInteger(p.bitLength() - 1, random);
            g = h.modPow(p.subtract(BigInteger.ONE).divide(q), p);
        } while (g.compareTo(BigInteger.ONE) <= 0);

        x = new BigInteger(q.bitLength() - 1, random);
        y = g.modPow(x, p);
    }

    public String sign(String message) {
        BigInteger hash = hashMessage(message);
        BigInteger k, r, s;

        do {
            do {
                k = new BigInteger(q.bitLength() - 1, random);
            } while (k.signum() == 0);

            r = g.modPow(k, p).mod(q);
        } while (r.signum() == 0);

        BigInteger kInv = k.modInverse(q);
        s = kInv.multiply(hash.add(x.multiply(r))).mod(q);

        return r.toString(16) + "\n" + s.toString(16);
    }

    public boolean verify(String message, String signatureHex) {
        String[] parts = signatureHex.trim().split("\\n");
        if (parts.length != 2) return false;

        BigInteger r = new BigInteger(parts[0], 16);
        BigInteger s = new BigInteger(parts[1], 16);

        if (r.signum() <= 0 || r.compareTo(q) >= 0 ||
                s.signum() <= 0 || s.compareTo(q) >= 0) return false;

        BigInteger hash = hashMessage(message);
        BigInteger w = s.modInverse(q);
        BigInteger u1 = hash.multiply(w).mod(q);
        BigInteger u2 = r.multiply(w).mod(q);

        BigInteger v = g.modPow(u1, p).multiply(y.modPow(u2, p)).mod(p).mod(q);
        return v.equals(r);
    }

    private BigInteger hashMessage(String message) {
        byte[] hashBytes = digest.digest(message.getBytes());
        return new BigInteger(1, hashBytes);
    }
}
