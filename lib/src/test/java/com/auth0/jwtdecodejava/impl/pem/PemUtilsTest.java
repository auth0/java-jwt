package com.auth0.jwtdecodejava.impl.pem;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

import static org.hamcrest.Matchers.is;

public class PemUtilsTest {

    private static final String PUBLIC_KEY_FILE = "src/test/resources/rsa_public.pem";


    private static final String PUBLIC_KEY_CONTENT = "-----BEGIN PUBLIC KEY-----\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuGbXWiK3dQTyCbX5xdE4\n" +
            "yCuYp0AF2d15Qq1JSXT/lx8CEcXb9RbDddl8jGDv+spi5qPa8qEHiK7FwV2KpRE9\n" +
            "83wGPnYsAm9BxLFb4YrLYcDFOIGULuk2FtrPS512Qea1bXASuvYXEpQNpGbnTGVs\n" +
            "WXI9C+yjHztqyL2h8P6mlThPY9E9ue2fCqdgixfTFIF9Dm4SLHbphUS2iw7w1JgT\n" +
            "69s7of9+I9l5lsJ9cozf1rxrXX4V1u/SotUuNB3Fp8oB4C1fLBEhSlMcUJirz1E8\n" +
            "AziMCxS+VrRPDM+zfvpIJg3JljAh3PJHDiLu902v9w+Iplu1WyoB2aPfitxEhRN0\n" +
            "YwIDAQAB\n" +
            "-----END PUBLIC KEY-----";
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void shouldReadPemFile() throws Exception {
        File pemFile = new File(PUBLIC_KEY_FILE);
        byte[] bytes = PemUtils.parsePEMFile(pemFile);
        PublicKey rsaKey = PemUtils.getPublicKey(bytes, "RSA");
        String stringValue = new String(rsaKey.getEncoded(), StandardCharsets.UTF_8);
        Assert.assertThat(stringValue, is(PUBLIC_KEY_CONTENT));
    }
}
