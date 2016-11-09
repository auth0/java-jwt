package com.auth0.jwt.algorithms;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;
import static org.mockito.Mockito.mock;

public class AlgorithmTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();


    @Test
    public void shouldThrowHMAC256VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        Algorithm.HMAC256(null);
    }

    @Test
    public void shouldThrowHMAC384VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        Algorithm.HMAC384(null);
    }

    @Test
    public void shouldThrowHMAC512VerificationWithNullSecret() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The Secret cannot be null");
        Algorithm.HMAC512(null);
    }

    @Test
    public void shouldThrowRSA256VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The RSAKey cannot be null");
        Algorithm.RSA256(null);
    }

    @Test
    public void shouldThrowRSA384VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The RSAKey cannot be null");
        Algorithm.RSA384(null);
    }

    @Test
    public void shouldThrowRSA512VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The RSAKey cannot be null");
        Algorithm.RSA512(null);
    }

    @Test
    public void shouldThrowECDSA256VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The ECKey cannot be null");
        Algorithm.ECDSA256(null);
    }

    @Test
    public void shouldThrowECDSA384VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The ECKey cannot be null");
        Algorithm.ECDSA384(null);
    }

    @Test
    public void shouldThrowECDSA512VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The ECKey cannot be null");
        Algorithm.ECDSA512(null);
    }

    @Test
    public void shouldCreateHMAC256Algorithm() throws Exception {
        Algorithm algorithm = Algorithm.HMAC256("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA256"));
        assertThat(algorithm.getName(), is("HS256"));
        assertThat(((HMACAlgorithm) algorithm).getSecret(), is("secret"));
    }

    @Test
    public void shouldCreateHMAC384Algorithm() throws Exception {
        Algorithm algorithm = Algorithm.HMAC384("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA384"));
        assertThat(algorithm.getName(), is("HS384"));
        assertThat(((HMACAlgorithm) algorithm).getSecret(), is("secret"));
    }

    @Test
    public void shouldCreateHMAC512Algorithm() throws Exception {
        Algorithm algorithm = Algorithm.HMAC512("secret");

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(HMACAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("HmacSHA512"));
        assertThat(algorithm.getName(), is("HS512"));
        assertThat(((HMACAlgorithm) algorithm).getSecret(), is("secret"));
    }

    @Test
    public void shouldCreateRSA256Algorithm() throws Exception {
        RSAKey key = mock(RSAKey.class);
        Algorithm algorithm = Algorithm.RSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
        assertThat(((RSAAlgorithm) algorithm).getKey(), is(key));
    }

    @Test
    public void shouldCreateRSA384Algorithm() throws Exception {
        RSAKey key = mock(RSAKey.class);
        Algorithm algorithm = Algorithm.RSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
        assertThat(((RSAAlgorithm) algorithm).getKey(), is(key));
    }

    @Test
    public void shouldCreateRSA512Algorithm() throws Exception {
        RSAKey key = mock(RSAKey.class);
        Algorithm algorithm = Algorithm.RSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
        assertThat(((RSAAlgorithm) algorithm).getKey(), is(key));
    }

    @Test
    public void shouldCreateECDSA256Algorithm() throws Exception {
        ECKey key = mock(ECKey.class);
        Algorithm algorithm = Algorithm.ECDSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withECDSA"));
        assertThat(algorithm.getName(), is("ES256"));
        assertThat(((ECDSAAlgorithm) algorithm).getKey(), is(key));
    }

    @Test
    public void shouldCreateECDSA384Algorithm() throws Exception {
        ECKey key = mock(ECKey.class);
        Algorithm algorithm = Algorithm.ECDSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withECDSA"));
        assertThat(algorithm.getName(), is("ES384"));
        assertThat(((ECDSAAlgorithm) algorithm).getKey(), is(key));
    }

    @Test
    public void shouldCreateECDSA512Algorithm() throws Exception {
        ECKey key = mock(ECKey.class);
        Algorithm algorithm = Algorithm.ECDSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(ECDSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withECDSA"));
        assertThat(algorithm.getName(), is("ES512"));
        assertThat(((ECDSAAlgorithm) algorithm).getKey(), is(key));
    }

    @Test
    public void shouldCreateNoneAlgorithm() throws Exception {
        Algorithm algorithm = Algorithm.none();

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(NoneAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("none"));
        assertThat(algorithm.getName(), is("none"));
    }

}