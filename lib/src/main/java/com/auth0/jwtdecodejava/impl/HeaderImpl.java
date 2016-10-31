package com.auth0.jwtdecodejava.impl;

import com.auth0.jwtdecodejava.enums.Algorithm;
import com.auth0.jwtdecodejava.enums.HSAlgorithm;
import com.auth0.jwtdecodejava.enums.NoneAlgorithm;
import com.auth0.jwtdecodejava.enums.RSAlgorithm;
import com.auth0.jwtdecodejava.interfaces.Header;
import com.fasterxml.jackson.databind.JsonNode;

import java.util.Map;

import static com.auth0.jwtdecodejava.impl.ClaimImpl.extractClaim;
import static com.auth0.jwtdecodejava.impl.Claims.*;

class HeaderImpl implements Header {
    private final Map<String, JsonNode> tree;

    HeaderImpl(Map<String, JsonNode> tree) {
        this.tree = tree;
    }

    @Override
    public Algorithm getAlgorithm() {
        String alg = extractClaim(ALGORITHM, tree).asString();
        return parseFrom(alg);
    }

    @Override
    public String getType() {
        return extractClaim(TYPE, tree).asString();
    }

    @Override
    public String getContentType() {
        return extractClaim(CONTENT_TYPE, tree).asString();
    }


    private Algorithm parseFrom(String algorithmName) {
        Algorithm algorithm = RSAlgorithm.resolveFrom(algorithmName);
        if (algorithm == null) {
            algorithm = HSAlgorithm.resolveFrom(algorithmName);
        }
        if (algorithm == null) {
            algorithm = NoneAlgorithm.resolveFrom(algorithmName);
        }
        return algorithm;
    }
}
