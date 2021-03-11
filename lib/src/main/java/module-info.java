module com.auth0.jwt {
    // remove transitive in next major release
    requires com.fasterxml.jackson.databind;
    // remove in next major release
    exports com.auth0.jwt.impl;

    exports com.auth0.jwt;
    exports com.auth0.jwt.algorithms;
    exports com.auth0.jwt.exceptions;
    exports com.auth0.jwt.interfaces;
}
