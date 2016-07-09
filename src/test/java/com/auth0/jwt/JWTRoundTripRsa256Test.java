package com.auth0.jwt;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.auth0.jwt.pem.PemReader.readPrivateKey;
import static com.auth0.jwt.pem.PemReader.readPublicKey;
import static com.auth0.jwt.pem.PemWriter.writePrivateKey;
import static com.auth0.jwt.pem.PemWriter.writePublicKey;
import static junit.framework.TestCase.*;

/**
 * Test that generates KeyPair - writes PEM files (private and public) to disk,
 * then reads in those PEM files (private and public) and uses them to Sign a JWT
 * and subsequently verify its correctness - hence "RoundTrip"
 */
public class JWTRoundTripRsa256Test {

    private static final int KEY_SIZE = 2048;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private File privateKeyPem;
    private File publicKeyPem;

    @Before
    public void createPemFiles() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        // create key pair
        final KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(KEY_SIZE);
        final KeyPair keyPair = generator.generateKeyPair();
        // write private key
        final RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        privateKeyPem = File.createTempFile("id_rsa", "");
        writePrivateKey(privateKey, "RSA PRIVATE KEY", privateKeyPem.getAbsolutePath());
        // write public key
        publicKeyPem = File.createTempFile("id_rsa", ".pub");
        final RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        writePublicKey(publicKey, "RSA PUBLIC KEY", publicKeyPem.getAbsolutePath());
    }

    @Test
    public void roundTripCreatingSignedTokenAndVerifyingUsingRs256Algo() throws NoSuchProviderException, NoSuchAlgorithmException, IOException, InvalidKeySpecException, SignatureException, InvalidKeyException, JWTAlgorithmException, JWTVerifyException {
        // read pem files
        final PrivateKey privateKey = readPrivateKey(privateKeyPem.getAbsolutePath());
        assertNotNull(privateKey);
        final PublicKey publicKey = readPublicKey(publicKeyPem.getAbsolutePath());
        assertNotNull(publicKey);
        // create and sign a JWT
        final String issuer = "https://arcseldon.auth0.com/";
        final String clientId = "xGXMKfEdcOcacZEU7Uq1mgWOtpUxBlL4"; // this is the audience
        final String name = "arcseldon";
        final String email = "arcseldon+test@gmail.com";
        final String subject = "auth0|576be978a93121cc48c7487d";
        final List<String> roles = new ArrayList<>();
        roles.add("ROLE_ADMIN");
        final long iat = System.currentTimeMillis() / 1000l;
        final long exp = iat + 3600L;
        final HashMap<String, Object> claims = new HashMap<>();
        claims.put("name", name);
        claims.put("email", email);
        claims.put("email_verified", "true");
        claims.put("iss", issuer);
        claims.put("roles", roles.toArray(new String[0]));
        claims.put("sub", subject);
        claims.put("aud", clientId);
        claims.put("exp", exp);
        claims.put("iat", iat);
        final JWTSigner jwtSigner = new JWTSigner(privateKey);
        final JWTSigner.Options options = new JWTSigner.Options();
        options.setAlgorithm(Algorithm.RS256);
        final String token = jwtSigner.sign(claims, options);
        assertNotNull(token);
        final JWTVerifier jwtVerifier = new JWTVerifier(publicKey);
        final Map<String, Object> verifiedClaims = jwtVerifier.verify(token);
        assertEquals(name, verifiedClaims.get("name"));
        assertEquals(email, verifiedClaims.get("email"));
        assertEquals("true", verifiedClaims.get("email_verified"));
        assertTrue(roles.equals((List<String>) verifiedClaims.get("roles")));
        assertEquals(issuer, verifiedClaims.get("iss"));
        assertEquals(subject, verifiedClaims.get("sub"));
        assertEquals(clientId, verifiedClaims.get("aud"));
        assertTrue(exp == (Integer) verifiedClaims.get("exp"));
        assertTrue(iat == (Integer) verifiedClaims.get("iat"));
    }

}
