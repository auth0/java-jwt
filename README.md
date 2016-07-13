# Java JWT

[![Build Status](https://travis-ci.org/auth0/java-jwt.svg?branch=master)](https://travis-ci.org/auth0/java-jwt)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/java-jwt/master.svg?style=flat-square)](https://codecov.io/github/auth0/java-jwt)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)
[![Maven Central](https://img.shields.io/maven-central/v/com.auth0/java-jwt.svg)](http://search.maven.org/#search%7Cga%7C1%7Ca%3A%22java-jwt%22)

An implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) developed against `draft-ietf-oauth-json-web-token-08`.

## Installation

### Maven

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>2.2.1</version>
</dependency>
```

### Gradle

```gradle
compile 'com.auth0.java-jwt:2.2.1'
```

## Usage

### Sign JWT (HS256)

```java
final String issuer = "https://mydomain.com/";
final String secret = "{{a secret used for signing}}";

final long iat = System.currentTimeMillis() / 1000l; // issued at claim 
final long exp = iat + 60L; // expires claim. In this case the token expires in 60 seconds

final JWTSigner signer = new JWTSigner(secret);
final HashMap<String, Object> claims = new HashMap<String, Object>();
claims.put("iss", issuer);
claims.put("exp", exp);
claims.put("iat", iat);

final String jwt = signer.sign(claims);
```

### Verify JWT (HS256)

```java
final String secret = "{{secret used for signing}}";
try {
    final JWTVerifier verifier = new JWTVerifier(secret);
    final Map<String,Object> claims= jwtVerifier.verify(jwt);
} catch (JWTVerifyException e) {
    // Invalid Token
}
```

### Validate aud & iss claims

```java
final String secret = "{{secret used for signing}}";
try {
    final JWTVerifier verifier = new JWTVerifier(secret, "{{my-audience}}", "{{my-issuer}}");
    final Map<String,Object> claims= jwtVerifier.verify(jwt);
} catch (JWTVerifyException e) {
    // Invalid Token
}
```


### Why another JSON Web Token implementation for Java?

We believe existing JWT implementations in Java are either too complex or not tested enough.
This library aims to be simple and achieve the right level of abstraction.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
