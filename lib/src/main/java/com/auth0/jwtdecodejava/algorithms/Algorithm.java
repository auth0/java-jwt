package com.auth0.jwtdecodejava.algorithms;

/**
 * The Algorithm class represents an algorithm to be used in the Signing or Verification process of a Token.
 */
public interface Algorithm {

    /**
     * Getter for the description required when instantiating a Mac or Signature object.
     *
     * @return the algorithm description.
     */
    String describe();

    /**
     * Getter for the name of this algorithm as referenced in the JWT standard.
     *
     * @return the algorithm name.
     */
    String name();

}
