package com.auth0.jwt;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import org.junit.Assert;
import org.junit.Test;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.ConcurrentHashMap;

public class KeyRotationTest {
    private static class IdentifiedKey {
        private final String id;
        private final KeyPair keyPair;

        IdentifiedKey(final String id, final KeyPair keyPair) {
            this.id = id;
            this.keyPair = keyPair;
        }

        ECPublicKey getPublic() {
            return (ECPublicKey) keyPair.getPublic();
        }

        ECPrivateKey getPrivate() {
            return (ECPrivateKey) keyPair.getPrivate();
        }
    }

    private static class KeyProvider implements ECDSAKeyProvider {
        private final long rotationFrequency;

        private final KeyPairGenerator keyPairGenerator;

        private final ConcurrentHashMap<String, IdentifiedKey> keys = new ConcurrentHashMap<>();
        private long currentKey = 0L;

        KeyProvider(final long rotationFrequency) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
            this.rotationFrequency = rotationFrequency;
            keyPairGenerator = KeyPairGenerator.getInstance("EC");
            keyPairGenerator.initialize(new ECGenParameterSpec("NIST P-256"), SecureRandom.getInstanceStrong());
        }

        @Override
        public ECPublicKey getPublicKeyById(final String keyId) {
            return keys.get(keyId).getPublic();
        }

        private IdentifiedKey generateKey(final String id) {
            return new IdentifiedKey(id, keyPairGenerator.generateKeyPair());
        }

        private IdentifiedKey currentKey() {
            final long now = System.currentTimeMillis() / rotationFrequency;
            final IdentifiedKey key;
            if (now != currentKey) {
                currentKey = now;
                key = generateKey(String.valueOf(now));
                keys.put(key.id, key);
            } else {
                key = keys.get(String.valueOf(now));
            }
            return key;
        }

        @Override
        public ECPrivateKey getPrivateKey() {
            return currentKey().getPrivate();
        }

        @Override
        public String getPrivateKeyId() {
            return currentKey().id;
        }
    }

    @Test
    public void generateAndValidate1000Tokens10sRotation() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        runTest(10_000, 10000);
    }

    @Test
    public void generateAndValidate1000Tokens1sRotation() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        runTest(1_000, 10000);
    }

    @Test
    public void generateAndValidate1000Tokens100msRotation() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        runTest(100, 10000);
    }

    @Test
    public void generateAndValidate1000Tokens10msRotation() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        runTest(10, 10000);
    }

    private void runTest(final long rotationFrequency, final int iterations) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        final KeyProvider provider = new KeyProvider(rotationFrequency);
        final Algorithm algorithm = Algorithm.ECDSA256(provider);
        final JWTVerifier verifier = JWTVerifier.init(algorithm).build();
        for (int i = 0; i < iterations; i++) {
            generateAndValidate(algorithm, verifier, i);
        }
    }

    private void generateAndValidate(final Algorithm algorithm, final JWTVerifier verifier, final int iteration) {
        try {
            final String token = JWT.create().sign(algorithm);
            verifier.verify(token);
        } catch (final JWTVerificationException e) {
            Assert.fail("Token " + iteration + " verification failed: " + e.getMessage());
        }
    }
}