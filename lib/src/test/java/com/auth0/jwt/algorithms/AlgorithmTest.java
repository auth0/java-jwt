package com.auth0.jwt.algorithms;

import com.auth0.jwt.interfaces.ECDSAKeyProvider;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchProviderException;
import java.security.interfaces.*;

import static org.hamcrest.Matchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.withSettings;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

public class AlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();


    @Test
    public void shouldThrowHMAC256InstanceWithNullSecretBytes() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        byte[] secret = null;
        Algorithm.HMAC256(secret);
    }

    @Test
    public void shouldThrowHMAC384InstanceWithNullSecretBytes() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        byte[] secret = null;
        Algorithm.HMAC384(secret);
    }

    @Test
    public void shouldThrowHMAC512InstanceWithNullSecretBytes() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        byte[] secret = null;
        Algorithm.HMAC512(secret);
    }

    @Test
    public void shouldThrowHMAC256InstanceWithNullSecret() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String secret = null;
        Algorithm.HMAC256(secret);
    }

    @Test
    public void shouldThrowHMAC384InstanceWithNullSecret() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String secret = null;
        Algorithm.HMAC384(secret);
    }

    @Test
    public void shouldThrowHMAC512InstanceWithNullSecret() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        String secret = null;
        Algorithm.HMAC512(secret);
    }

    @Test
    public void shouldThrowRSA256InstanceWithNullKey() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        RSAKey key = null;
        Algorithm.RSA256(key);
    }

    @Test
    public void shouldThrowRSA256InstanceWithNullKeys() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        Algorithm.RSA256(null, null);
    }

    @Test
    public void shouldThrowRSA256InstanceWithNullKeyProvider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Key Provider cannot be null.");
        RSAKeyProvider provider = null;
        Algorithm.RSA256(provider);
    }

    @Test
    public void shouldThrowRSA384InstanceWithNullKey() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        RSAKey key = null;
        Algorithm.RSA384(key);
    }

    @Test
    public void shouldThrowRSA384InstanceWithNullKeys() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        Algorithm.RSA384(null, null);
    }

    @Test
    public void shouldThrowRSA384InstanceWithNullKeyProvider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Key Provider cannot be null.");
        RSAKeyProvider provider = null;
        Algorithm.RSA384(provider);
    }

    @Test
    public void shouldThrowRSA512InstanceWithNullKey() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        RSAKey key = null;
        Algorithm.RSA512(key);
    }

    @Test
    public void shouldThrowRSA512InstanceWithNullKeys() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        Algorithm.RSA512(null, null);
    }

    @Test
    public void shouldThrowRSA512InstanceWithNullKeyProvider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Key Provider cannot be null.");
        RSAKeyProvider provider = null;
        Algorithm.RSA512(provider);
    }

    @Test
    public void shouldThrowECDSA256InstanceWithNullKey() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        ECKey key = null;
        Algorithm.ECDSA256(key);
    }

    @Test
    public void shouldThrowECDSA256InstanceWithNullKeys() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        Algorithm.ECDSA256(null, null);
    }

    @Test
    public void shouldThrowECDSA256InstanceWithNullKeyProvider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Key Provider cannot be null.");
        ECDSAKeyProvider provider = null;
        Algorithm.ECDSA256(provider);
    }

    @Test
    public void shouldThrowECDSA384InstanceWithNullKey() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        ECKey key = null;
        Algorithm.ECDSA384(key);
    }

    @Test
    public void shouldThrowECDSA384InstanceWithNullKeys() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        Algorithm.ECDSA384(null, null);
    }

    @Test
    public void shouldThrowECDSA384InstanceWithNullKeyProvider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Key Provider cannot be null.");
        ECDSAKeyProvider provider = null;
        Algorithm.ECDSA384(provider);
    }

    @Test
    public void shouldThrowECDSA512InstanceWithNullKey() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        ECKey key = null;
        Algorithm.ECDSA512(key);
    }

    @Test
    public void shouldThrowECDSA512InstanceWithNullKeys() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("Both provided Keys cannot be null.");
        Algorithm.ECDSA512(null, null);
    }

    @Test
    public void shouldThrowECDSA512InstanceWithNullKeyProvider() {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Key Provider cannot be null.");
        ECDSAKeyProvider provider = null;
        Algorithm.ECDSA512(provider);
    }

    @Test
    public void shouldCreateHMAC256AlgorithmWithBytes() {
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes(StandardCharsets.UTF_8));

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA256"));
        assertThat(algorithm.getName(), is("HS256"));
    }

    @Test
    public void shouldCreateHMAC384AlgorithmWithBytes() {
        Algorithm algorithm = Algorithm.HMAC384("secret".getBytes(StandardCharsets.UTF_8));

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA384"));
        assertThat(algorithm.getName(), is("HS384"));
    }

    @Test
    public void shouldCreateHMAC512AlgorithmWithBytes() {
        Algorithm algorithm = Algorithm.HMAC512("secret".getBytes(StandardCharsets.UTF_8));

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA512"));
        assertThat(algorithm.getName(), is("HS512"));
    }

    @Test
    public void shouldCreateHMAC256AlgorithmWithString() {
        Algorithm algorithm = Algorithm.HMAC256("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA256"));
        assertThat(algorithm.getName(), is("HS256"));
    }

    @Test
    public void shouldCreateHMAC384AlgorithmWithString() {
        Algorithm algorithm = Algorithm.HMAC384("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA384"));
        assertThat(algorithm.getName(), is("HS384"));
    }

    @Test
    public void shouldCreateHMAC512AlgorithmWithString() {
        Algorithm algorithm = Algorithm.HMAC512("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA512"));
        assertThat(algorithm.getName(), is("HS512"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithPublicKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPublicKey.class));
        Algorithm algorithm = Algorithm.RSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithPrivateKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPrivateKey.class));
        Algorithm algorithm = Algorithm.RSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithBothKeys() {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = Algorithm.RSA256(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA256AlgorithmWithProvider() {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        Algorithm algorithm = Algorithm.RSA256(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithPublicKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPublicKey.class));
        Algorithm algorithm = Algorithm.RSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithPrivateKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPrivateKey.class));
        Algorithm algorithm = Algorithm.RSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithBothKeys() {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = Algorithm.RSA384(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA384AlgorithmWithProvider() {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        Algorithm algorithm = Algorithm.RSA384(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithPublicKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPublicKey.class));
        Algorithm algorithm = Algorithm.RSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithPrivateKey() {
        RSAKey key = mock(RSAKey.class, withSettings().extraInterfaces(RSAPrivateKey.class));
        Algorithm algorithm = Algorithm.RSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithBothKeys() {
        RSAPublicKey publicKey = mock(RSAPublicKey.class);
        RSAPrivateKey privateKey = mock(RSAPrivateKey.class);
        Algorithm algorithm = Algorithm.RSA512(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateRSA512AlgorithmWithProvider() {
        RSAKeyProvider provider = mock(RSAKeyProvider.class);
        Algorithm algorithm = Algorithm.RSA512(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithPublicKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPublicKey.class));
        Algorithm algorithm = Algorithm.ECDSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithPrivateKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPrivateKey.class));
        Algorithm algorithm = Algorithm.ECDSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithBothKeys() {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = Algorithm.ECDSA256(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA256AlgorithmWithProvider() {
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        Algorithm algorithm = Algorithm.ECDSA256(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithPublicKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPublicKey.class));
        Algorithm algorithm = Algorithm.ECDSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithPrivateKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPrivateKey.class));
        Algorithm algorithm = Algorithm.ECDSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithBothKeys() {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = Algorithm.ECDSA384(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA384AlgorithmWithProvider() {
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        Algorithm algorithm = Algorithm.ECDSA384(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithPublicKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPublicKey.class));
        Algorithm algorithm = Algorithm.ECDSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithPrivateKey() {
        ECKey key = mock(ECKey.class, withSettings().extraInterfaces(ECPrivateKey.class));
        Algorithm algorithm = Algorithm.ECDSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithBothKeys() {
        ECPublicKey publicKey = mock(ECPublicKey.class);
        ECPrivateKey privateKey = mock(ECPrivateKey.class);
        Algorithm algorithm = Algorithm.ECDSA512(publicKey, privateKey);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateECDSA512AlgorithmWithProvider() {
        ECDSAKeyProvider provider = mock(ECDSAKeyProvider.class);
        Algorithm algorithm = Algorithm.ECDSA512(provider);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
    }

    @Test
    public void shouldCreateNoneAlgorithm() {
        Algorithm algorithm = Algorithm.none();

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(NoneAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("none"));
        assertThat(algorithm.getName(), is("none"));
    }

    @Test
    public void shouldForwardHeaderPayloadSignatureToSiblingSignMethodForBackwardsCompatibility() throws Exception {
        Algorithm algorithm = mock(Algorithm.class);

        ArgumentCaptor<byte[]> contentCaptor = ArgumentCaptor.forClass(byte[].class);

        byte[] header = new byte[]{0x00, 0x01, 0x02};
        byte[] payload = new byte[]{0x04, 0x05, 0x06};

        byte[] signature = new byte[]{0x10, 0x11, 0x12};
        when(algorithm.sign(any(byte[].class), any(byte[].class))).thenCallRealMethod();
        when(algorithm.sign(contentCaptor.capture())).thenReturn(signature);

        byte[] sign = algorithm.sign(header, payload);

        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        bout.write(header);
        bout.write('.');
        bout.write(payload);
        
        assertThat(sign, is(signature));
        assertThat(contentCaptor.getValue(), is(bout.toByteArray()));
    }
}