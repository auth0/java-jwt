package com.auth0.jwtdecodejava.interfaces;

import com.auth0.jwtdecodejava.enums.Algorithm;

public interface Header {

    Algorithm getAlgorithm();

    String getType();

    String getContentType();

}
