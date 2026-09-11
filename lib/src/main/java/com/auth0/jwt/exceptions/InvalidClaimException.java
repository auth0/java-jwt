package com.auth0.jwt.exceptions;

/**
 * The exception that will be thrown while verifying Claims of a JWT.
 */
public class InvalidClaimException extends JWTVerificationException {

    private final String claimName;

    public InvalidClaimException(String message, String claimName) {
        super(message);
        this.claimName = claimName;
    }

    /**
     * This method can be used to fetch the name for which the Claim verification failed.
     *
     * @return The claim name for which the verification failed.
     */
    public String getClaimName() {
        return claimName;
    }

}