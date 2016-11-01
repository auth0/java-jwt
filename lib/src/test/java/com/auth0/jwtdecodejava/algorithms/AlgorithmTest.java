package com.auth0.jwtdecodejava.algorithms;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.security.PublicKey;

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
        exception.expectMessage("The PublicKey cannot be null");
        Algorithm.RSA256(null);
    }

    @Test
    public void shouldThrowRSA384VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The PublicKey cannot be null");
        Algorithm.RSA384(null);
    }

    @Test
    public void shouldThrowRSA512VerificationWithNullPublicKey() throws Exception {
        exception.expect(IllegalArgumentException.class);
        exception.expectMessage("The PublicKey cannot be null");
        Algorithm.RSA512(null);
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
        PublicKey key = mock(PublicKey.class);
        Algorithm algorithm = Algorithm.RSA256(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA256withRSA"));
        assertThat(algorithm.getName(), is("RS256"));
        assertThat(((RSAAlgorithm) algorithm).getPublicKey(), is(key));
    }

    @Test
    public void shouldCreateRSA384Algorithm() throws Exception {
        PublicKey key = mock(PublicKey.class);
        Algorithm algorithm = Algorithm.RSA384(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA384withRSA"));
        assertThat(algorithm.getName(), is("RS384"));
        assertThat(((RSAAlgorithm) algorithm).getPublicKey(), is(key));
    }

    @Test
    public void shouldCreateRSA512Algorithm() throws Exception {
        PublicKey key = mock(PublicKey.class);
        Algorithm algorithm = Algorithm.RSA512(key);

        assertThat(algorithm, is(notNullValue()));
        assertThat(algorithm, is(instanceOf(RSAAlgorithm.class)));
        assertThat(algorithm.getDescription(), is("SHA512withRSA"));
        assertThat(algorithm.getName(), is("RS512"));
        assertThat(((RSAAlgorithm) algorithm).getPublicKey(), is(key));
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