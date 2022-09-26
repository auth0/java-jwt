package com.auth0.jwt.algorithms;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.fail;

public abstract class CryptoTestHelper {

    private static final Pattern authHeaderPattern = Pattern.compile("^([\\w-]+)\\.([\\w-]+)\\.([\\w-]+)");

    public static String asJWT(Algorithm algorithm, String header, String payload) {
        byte[] signatureBytes = algorithm.sign(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8));
        String jwtSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        return String.format("%s.%s.%s", header, payload, jwtSignature);
    }

    public static String asJWT(Algorithm algorithm, String header, String payload, String providerName) throws NoSuchProviderException {
        byte[] signatureBytes = algorithm.sign(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8), providerName);
        String jwtSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        return String.format("%s.%s.%s", header, payload, jwtSignature);
    }

    public static String asJWT(Algorithm algorithm, String header, String payload, Provider provider) {
        byte[] signatureBytes = algorithm.sign(header.getBytes(StandardCharsets.UTF_8), payload.getBytes(StandardCharsets.UTF_8), provider);
        String jwtSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);
        return String.format("%s.%s.%s", header, payload, jwtSignature);
    }

    public static void assertSignatureValue(String jwt, String expectedSignature) {
        String jwtSignature = jwt.substring(jwt.lastIndexOf('.') + 1);
        assertThat(jwtSignature, is(expectedSignature));
    }

    public static void assertSignaturePresent(String jwt) {
        Matcher matcher = authHeaderPattern.matcher(jwt);
        if (!matcher.find() || matcher.groupCount() < 3) {
            fail("No signature present in " + jwt);
        }

        assertThat(matcher.group(3), not(is(emptyString())));
    }
}
