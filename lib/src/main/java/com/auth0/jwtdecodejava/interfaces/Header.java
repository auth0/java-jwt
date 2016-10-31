package com.auth0.jwtdecodejava.interfaces;

import com.auth0.jwtdecodejava.algorithms.Algorithm;

public interface Header {

    Algorithm getAlgorithm();

    String getType();

    String getContentType();

}
