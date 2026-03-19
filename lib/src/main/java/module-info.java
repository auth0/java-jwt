module com.auth0.jwt {
    requires tools.jackson.core;
    requires tools.jackson.databind;

    exports com.auth0.jwt;
    exports com.auth0.jwt.algorithms;
    exports com.auth0.jwt.exceptions;
    exports com.auth0.jwt.interfaces;
}
