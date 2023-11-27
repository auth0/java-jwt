package com.auth0.jwt.algorithms;

import com.auth0.jwt.exceptions.SignatureGenerationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * The Algorithm class represents an algorithm to be used in the Signing or Verification process of a Token.
 * <p>
 * This class and its subclasses are thread-safe.
 */
@SuppressWarnings("WeakerAccess")
public abstract class Algorithm {

    private final String name;
    private final String description;


    public static Algorithm none() {
        return new NoneAlgorithm();
    }

    protected Algorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    /**
     * Getter for the Id of the Private Key used to sign the tokens.
     * This is usually specified as the `kid` claim in the Header.
     *
     * @return the Key Id that identifies the Signing Key or null if it's not specified.
     */
    public String getSigningKeyId() {
        return null;
    }

    /**
     * Getter for the name of this Algorithm, as defined in the JWT Standard. i.e. "HS256"
     *
     * @return the algorithm name.
     */
    public String getName() {
        return name;
    }

    /**
     * Getter for the description of this Algorithm,
     * required when instantiating a Mac or Signature object. i.e. "HmacSHA256"
     *
     * @return the algorithm description.
     */
    String getDescription() {
        return description;
    }

    @Override
    public String toString() {
        return description;
    }

    /**
     * Verify the given token using this Algorithm instance.
     *
     * @param jwt the already decoded JWT that it's going to be verified.
     * @throws SignatureVerificationException if the Token's Signature is invalid,
     *                                        meaning that it doesn't match the signatureBytes,
     *                                        or if the Key is invalid.
     */
    public abstract void verify(DecodedJWT jwt) throws SignatureVerificationException;

    /**
     * Sign the given content using this Algorithm instance.
     *
     * @param headerBytes  an array of bytes representing the base64 encoded header content
     *                     to be verified against the signature.
     * @param payloadBytes an array of bytes representing the base64 encoded payload content
     *                     to be verified against the signature.
     * @return the signature in a base64 encoded array of bytes
     * @throws SignatureGenerationException if the Key is invalid.
     */
    public byte[] sign(byte[] headerBytes, byte[] payloadBytes) throws SignatureGenerationException {
        // default implementation; keep around until sign(byte[]) method is removed
        byte[] contentBytes = new byte[headerBytes.length + 1 + payloadBytes.length];

        System.arraycopy(headerBytes, 0, contentBytes, 0, headerBytes.length);
        contentBytes[headerBytes.length] = (byte) '.';
        System.arraycopy(payloadBytes, 0, contentBytes, headerBytes.length + 1, payloadBytes.length);

        return sign(contentBytes);
    }

    /**
     * Sign the given content using this Algorithm instance.
     * To get the correct JWT Signature, ensure the content is in the format {HEADER}.{PAYLOAD}
     *
     * @param contentBytes an array of bytes representing the base64 encoded content
     *                     to be verified against the signature.
     * @return the signature in a base64 encoded array of bytes
     * @throws SignatureGenerationException if the Key is invalid.
     */

    public abstract byte[] sign(byte[] contentBytes) throws SignatureGenerationException;

}
