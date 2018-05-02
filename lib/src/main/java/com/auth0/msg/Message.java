package com.auth0.msg;

import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.JsonProcessingException;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Map;

/**
 * This interface all the methods related to message processing.
 */
public interface Message {

    /**
     * Serialize the content of this instance (the claims map) into a JSON object
     * @return a JSON String representation of the message
     * @throws SerializationException
     */
    String toJson() throws SerializationException, JsonProcessingException;

    /**
     * Serialize the content of the claims map into an UrlEncoded string
     * @return a urlEncoded string
     * @throws SerializationException
     */
    String toUrlEncoded() throws SerializationException, JsonProcessingException;

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param Key the signing key
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimsException
     */
    String toJwt(Key key, Algorithm algorithm) throws InvalidClaimsException, SerializationException;

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param KeyJar the signing keyjar
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimsException
     */
    String toJwt(KeyJar jar, Algorithm algorithm) throws InvalidClaimsException, SerializationException;

    /**
     * Logic to extract from the string the values
     * @param input The JSON String representation of a message
     */
    void fromJson(String input);

    /**
     * @param input the urlEncoded String representation of a message
     */
    void fromUrlEncoded(String input) throws MalformedURLException, IOException;

    /**
     *
     * @param input the jwt String representation of a message
     * @param KeyJar that might contain the necessary key
     */
    void fromJwt(String input, KeyJar jar);

    /**
     * verify that the required claims are present
     * @return whether the verification passed
     */
    boolean verify();

    /**
     *
     * @param name of the claim
     * @param value of the claim
     */
    void addClaim(Claim name, Object value);

    /**
     *
     * @return Map of claims
     * @throws InvalidClaimsException
     */
    Map<Claim, Object> getClaims() throws InvalidClaimsException;

    /**
     *
     * @param String authorization endpoint
     */
    String getRequestWithEndpoint(String authorizationEndpoint, DataLocation location);

    /**
     * @return the error object representing an error in verification
     */
    Error getError();

    /**
     * @return boolean for whether there is an error in verification
     */
    boolean hasError();
}
