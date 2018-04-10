package com.auth0.msg;

import com.auth0.jwt.algorithms.Algorithm;
import org.apache.commons.codec.binary.Hex;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class AbstractMessage implements Message {
    private Map<String, Object> claims;
    private String input;
    private Error error = null;
    private boolean verified = false;

    protected AbstractMessage(Map<String, Object> claims) {
        this.claims = claims;
    }

    /**
     * Returns a hashmap representation of the contents of the urlEncoded string
     * which is passed in as a parameter
     *
     * @param urlEncoded the urlEncoded String representation of a message
     * @return a map of the key value pairs encoded in the string parameter
     */
    private static Map<String, Object> claimsFromUrlEncoded(String urlEncoded) throws Exception {
        //Logic to extract from the string the values
        Map<String, Object> values = new HashMap<String, Object>();
        return values;
    }

    /**
     * @param input the urlEncoded String representation of a message
     * @return a Message representation of the UrlEncoded string
     */
    public Message fromUrlEncoded(String input) {
        this.input = input;
        //This will have logic to parse urlencoded to claims
        return this;
    }

    /**
     * Takes the claims of this instance of the AbstractMessage class and serializes them
     * to an urlEncoded string
     *
     * @return an urlEncoded string
     */
    public String toUrlEncoded() {
        // Serialize the content of this instance (the claims map) into an UrlEncoded string
        return "";
    }

    /**
     * Logic to extract from the string the values
     *
     * @param input The JSON String representation of a message
     * @return a Message representation of the Json
     */
    public Message fromJson(String input) {
        this.input = input;
        //This will have logic to parse json to claims
        return this;
    }

    /**
     * Takes the claims of this instance of the AbstractMessage class and serializes them
     * to a json string
     *
     * @return a JSON String representation in the form of a hashMap mapping string -> string
     */
    public String toJson() {
        if (this.error != null) {
            //This should be custom exception
            throw new InvalidClaimsException("Error present cannot serialize message");
        }
        return "";
    }

    /**
     * @param input the jwt String representation of a message
     * @param Key   that might contain the necessary key
     * @return a ResponseMessage representation of the JWT
     */
    public Message fromJwt(String input, Key key) {
        this.input = input;
        //This will have logic to parse Jwt to claims
        return this;
    }

    /**
     * @param input the jwt String representation of a message
     * @param KeyJar that might contain the necessary key
     * @return a Message representation of the JWT
     */
    public Message fromJwt(String input, KeyJar jar) {
        this.input = input;
        //This will have logic to parse Jwt to claims
        return this;
    }

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param KeyJar the signing keyjar
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimsException
     */
    public String toJwt(KeyJar keyjar, Algorithm algorithm) throws
            InvalidClaimsException {
        return null;
    }

    /**
     * Serialize the content of this instance (the claims map) into a jwt string
     * @param Key the signing key
     * @param String the algorithm to use in signing the JWT
     * @return a jwt String
     * @throws InvalidClaimsException
     */
    public String toJwt(Key key, Algorithm algorithm) throws InvalidClaimsException {
        return null;
    }

    /**
     * verify that the required claims are present
     * @return whether the verification passed
     */
    public boolean verify() {
        //This method will set error if verification fails
        return true;
    }

    /**
     * add the claim to this instance of message
     * @param ClaimType the name of the claim
     * @param Object the value of the claim to add to this instance of Message
     * @return a Message representation of the Json
     */
    public void addClaim(ClaimType name, Object value) {
        // verify 'name’ is a valid claim and then check the type is valid before adding
    }

    /**
     * @param endpoint to base the request url on
     * @return a String for the representation of the formatted request
     */
    public String getRequestWithEndpoint(String authorizationEndpoint) {
        return null;
    }

    /**
     * @return Error an object representing the error status of claims verification
     */
    public Error getError() {
        return error;
    }


    /**
     * @return List of the list of standard optional claims for this messsage type
     */
    protected List<ClaimType> getOptionalClaims(){
        return Collections.emptyList();
    }

    /**
     * @return List of the list of standard required claims for this messsage type
     */
    abstract protected List<ClaimType> getRequiredClaims();

    @Override
    public String toString() {
        //Override to return user friendly value
        return super.toString();
    }
}
