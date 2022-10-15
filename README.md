# Java JWT

A Java implementation of [JSON Web Token (JWT) - RFC 7519](https://tools.ietf.org/html/rfc7519)

[![CircleCI](https://img.shields.io/circleci/project/github/auth0/java-jwt.svg?style=flat-square)](https://circleci.com/gh/auth0/java-jwt/tree/master)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/java-jwt.svg?style=flat-square)](https://codecov.io/github/auth0/java-jwt)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](https://doge.mit-license.org/)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0/java-jwt.svg?style=flat-square)](https://mvnrepository.com/artifact/com.auth0/java-jwt)
[![javadoc](https://javadoc.io/badge2/com.auth0/auth0/javadoc.svg)](https://javadoc.io/doc/com.auth0/java-jwt)

:books: [Documentation](#documentation) - :rocket: [Getting Started](#getting-started) - :computer: [API Reference](#api-reference) :speech_balloon: [Feedback](#feedback)

## Documentation
- [Examples](./EXAMPLES.md) - code samples for common auth0-java scenarios.
- [Docs site](https://www.auth0.com/docs) - explore our docs site and learn more about Auth0.

## Getting Started

### Requirements

This library is supported for Java LTS versions 8, 11, and 17. For issues on non-LTS versions above 8, consideration will be given on a case-by-case basis.

> `auth0-java` is intended for server-side JVM applications. Android applications should use the [Auth0.Android SDK](https://github.com/auth0/auth0.android).

`java-jwt` supports the following algorithms for both signing and verification:

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| HS256 | HMAC256 | HMAC with SHA-256 |
| HS384 | HMAC384 | HMAC with SHA-384 |
| HS512 | HMAC512 | HMAC with SHA-512 |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | RSA384 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | RSA512 | RSASSA-PKCS1-v1_5 with SHA-512 |
| ES256 | ECDSA256 | ECDSA with curve P-256 and SHA-256 |
| ES384 | ECDSA384 | ECDSA with curve P-384 and SHA-384 |
| ES512 | ECDSA512 | ECDSA with curve P-521 and SHA-512 |

> Note - Support for ECDSA with curve secp256k1 and SHA-256 (ES256K) has been dropped since it has been [disabled in Java 15](https://www.oracle.com/java/technologies/javase/15-relnote-issues.html#JDK-8237219)

> :warning:  **Important security note:** JVM has a critical vulnerability for ECDSA Algorithms - [CVE-2022-21449](https://nvd.nist.gov/vuln/detail/CVE-2022-21449). Please review the details of the vulnerability and update your environment.
### Installation

Add the dependency via Maven:

```xml
<dependency>
  <groupId>com.auth0</groupId>
  <artifactId>java-jwt</artifactId>
  <version>4.1.0</version>
</dependency>
```

or Gradle:

```gradle
implementation 'com.auth0:jva-jwt:4.1.0'
```

### Create a JWT

Use `JWT.create()`, configure the claims, and then call `sign(algorithm)` to sign the JWT.

The example below demonstrates this using the `RS256` signing algorithm:

```java
try {
    Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
    String token = JWT.create()
        .withIssuer("auth0")
        .sign(algorithm);
} catch (JWTCreationException exception){
    // Invalid Signing configuration / Couldn't convert Claims.
}
```

### Verify a JWT

Create a `JWTVerifier` passing the `Algorithm`, and specify any required claim values.

The following example uses `RS256` to verify the JWT.

```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
DecodedJWT decodedJWT;
try {
    Algorithm algorithm = Algorithm.RSA256(rsaPublicKey, rsaPrivateKey);
    JWTVerifier verifier = JWT.require(algorithm)
        // specify an specific claim validations
        .withIssuer("auth0")
        // reusable verifier instance
        .build();
        
    decodedJWT jwt = verifier.verify(token);
} catch (JWTVerificationException exception){
    // Invalid signature/claims
}
```

If the token has an invalid signature or the Claim requirement is not met, a `JWTVerificationException` will be thrown.

See the [examples](./EXAMPLES.md) and [JavaDocs](https://javadoc.io/doc/com.auth0/java-jwt/latest) for additional documentation.

## API Reference

- [java-jwt JavaDocs](https://javadoc.io/doc/com.auth0/java-jwt/latest)

## Feedback

### Contributing

We appreciate feedback and contribution to this repo! Before you get started, please see the following:

- [Auth0's general contribution guidelines](https://github.com/auth0/open-source-template/blob/master/GENERAL-CONTRIBUTING.md)
- [Auth0's code of conduct guidelines]((https://github.com/auth0/open-source-template/blob/master/CODE-OF-CONDUCT.md))

### Raise an issue
To provide feedback or report a bug, [please raise an issue on our issue tracker](https://github.com/auth0/java-jwt/issues).

### Vulnerability Reporting
Please do not report security vulnerabilities on the public Github issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

---

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="./assets/auth0_light_mode.png"   width="150">
    <source media="(prefers-color-scheme: dark)" srcset="./assets/auth0_dark_mode.png" width="150">
    <img alt="Auth0 Logo" src="./auth0_light_mode.png" width="150">
  </picture>
</p>
<p align="center">Auth0 is an easy to implement, adaptable authentication and authorization platform. To learn more checkout <a href="https://auth0.com/why-auth0">Why Auth0?</a></p>
<p align="center">
This project is licensed under the MIT license. See the <a href="./LICENSE"> LICENSE</a> file for more info.</p>
