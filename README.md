

# Java JWT

[![Build Status](https://travis-ci.org/auth0/java-jwt.svg?branch=v3)](https://travis-ci.org/auth0/java-jwt)
[![Coverage Status](https://img.shields.io/codecov/c/github/auth0/java-jwt/v3.svg?style=flat-square)](https://codecov.io/github/auth0/java-jwt)
[![License](http://img.shields.io/:license-mit-blue.svg?style=flat)](http://doge.mit-license.org)

A Java implementation of [JSON Web Tokens (draft-ietf-oauth-json-web-token-08)](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

## Installation

### Maven

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.0.2</version>
</dependency>
```

### Gradle

```gradle
compile 'com.auth0:java-jwt:3.0.2'
```

## Available Algorithms

The library implements JWT Verification and Signing using the following algorithms:

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

## Usage

### Decode a Token

```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
try {
    JWT jwt = JWT.decode(token);
} catch (JWTDecodeException exception){
    //Invalid token
}
```

If the token has an invalid syntax or the header or payload are not JSONs, a `JWTDecodeException` will raise.


### Create and Sign a Token

You'll first need to create a `JWTCreator` instance by calling `JWT.create()`. Use the builder to define the custom Claims your token needs to have. Finally to get the String token call `sign()` and pass the Algorithm instance.

* Example using `HS256`

```java
try {
    String token = JWT.create()
        .withIssuer("auth0")
        .sign(Algorithm.HMAC256("secret"));
} catch (JWTCreationException exception){
    //Invalid Signing configuration / Couldn't convert Claims.
}
```

* Example using `RS256`

```java
PrivateKey key = //Get the key instance
try {
    String token = JWT.create()
        .withIssuer("auth0")
        .sign(Algorithm.RSA256(key));
} catch (JWTCreationException exception){
    //Invalid Signing configuration / Couldn't convert Claims.
}
```

If a Claim couldn't be converted to JSON or the Key used in the signing process was invalid a `JWTCreationException` will raise.


### Verify a Token

You'll first need to create a `JWTVerifier` instance by calling `JWT.require()` and passing the Algorithm instance. If you require the token to have specific Claim values, use the builder to define them. The instance returned by the method `build()` is reusable, so you can define it once and use it to verify different tokens. Finally call `verifier.verify()` passing the token.

* Example using `HS256`

```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
try {
    JWTVerifier verifier = JWT.require(Algorithm.HMAC256("secret"))
        .withIssuer("auth0")
        .build(); //Reusable verifier instance
    JWT jwt = verifier.verify(token);
} catch (JWTVerificationException exception){
    //Invalid signature/claims
}
```

* Example using `RS256`

```java
String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXUyJ9.eyJpc3MiOiJhdXRoMCJ9.AbIJTDMFc7yUa5MhvcP03nJPyCPzZtQcGEp-zWfOkEE";
PublicKey key = //Get the key instance
try {
    JWTVerifier verifier = JWT.require(Algorithm.RSA256(key))
        .withIssuer("auth0")
        .build(); //Reusable verifier instance
    JWT jwt = verifier.verify(token);
} catch (JWTVerificationException exception){
    //Invalid signature/claims
}
```

If the token has an invalid signature or the Claim requirement is not met, a `JWTVerificationException` will raise.


#### Time Validation

The JWT token may include DateNumber fields that can be used to validate that:
* The token was issued in a past date `"iat" < TODAY`
* The token hasn't expired yet `"exp" > TODAY` and
* The token can already be used. `"nbf" > TODAY`

When verifying a token the time validation occurs automatically, resulting in a `JWTVerificationException` being throw when the values are invalid. If any of the previous fields are missing they won't be considered in this validation.

To specify a **leeway window** in which the Token should still be considered valid, use the `acceptLeeway()` method in the `JWTVerifier` builder and pass a positive seconds value. This applies to every item listed above.

```java
JWTVerifier verifier = JWT.require(Algorithm.RSA256(key))
    .acceptLeeway(1) // 1 sec for nbf, iat and exp
    .build();
```

You can also specify a custom value for a given Date claim and override the default one for only that claim.

```java
JWTVerifier verifier = JWT.require(Algorithm.RSA256(key))
    .acceptLeeway(1)   //1 sec for nbf and iat
    .acceptExpiresAt(5)   //5 secs for exp
    .build();
```


### Header Claims

#### Algorithm ("alg")

Returns the Algorithm value or null if it's not defined in the Header.

```java
String algorithm = jwt.getAlgorithm();
```

#### Type ("typ")

Returns the Type value or null if it's not defined in the Header.

```java
String type = jwt.getType();
```

#### Content Type ("cty")

Returns the Content Type value or null if it's not defined in the Header.

```java
String contentType = jwt.getContentType();
```

#### Key Id ("kid")

Returns the Key Id value or null if it's not defined in the Header.

```java
String keyId = jwt.getKeyId();
```

#### Private Claims

Additional Claims defined in the token's Header can be obtained by calling `getHeaderClaim()` and passing the Claim name. A Claim will always be returned, even if it can't be found. You can check if a Claim's value is null by calling `claim.isNull()`.

```java
Claim claim = jwt.getHeaderClaim("owner");
```


### Payload Claims

#### Issuer ("iss")

Returns the Issuer value or null if it's not defined in the Payload.

```java
String issuer = jwt.getIssuer();
```

#### Subject ("sub")

Returns the Subject value or null if it's not defined in the Payload.

```java
String subject = jwt.getSubject();
```

#### Audience ("aud")

Returns the Audience value or null if it's not defined in the Payload.

```java
List<String> audience = jwt.getAudience();
```

#### Expiration Time ("exp")

Returns the Expiration Time value or null if it's not defined in the Payload.

```java
Date expiresAt = jwt.getExpiresAt();
```

#### Not Before ("nbf")

Returns the Not Before value or null if it's not defined in the Payload.

```java
Date notBefore = jwt.getNotBefore();
```

#### Issued At ("iat")

Returns the Issued At value or null if it's not defined in the Payload.

```java
Date issuedAt = jwt.getIssuedAt();
```

#### JWT ID ("jti")

Returns the JWT ID value or null if it's not defined in the Payload.

```java
String id = jwt.getId();
```

#### Private Claims

Additional Claims defined in the token's Payload can be obtained by calling `getClaim()` and passing the Claim name. A Claim will always be returned, even if it can't be found. You can check if a Claim's value is null by calling `claim.isNull()`.

```java
Claim claim = jwt.getClaim("isAdmin");
```

When creating a Token with the `JWT.create()` you can specify a custom Claim by calling `withClaim()` and passing both the name and the value.

```java
JWT.create()
    .withClaim("name", 123)
    .sign(Algorithm.HMAC256("secret"));
```

You can also verify custom Claims on the `JWT.require()` by calling `withClaim()` and passing both the name and the required value.

```java
JWT.require(Algorithm.HMAC256("secret"))
    .withClaim("name", 123)
    .build()
    .verify("my.jwt.token");
```

> The value of the custom Claim in all the cases must be of a `Integer`, `Double`, `Date`, `String`, or `Boolean` class.


### Claim Class
The Claim class is a wrapper for the Claim values. It allows you to get the Claim as different class types. The available helpers are:

#### Primitives
* **asBoolean()**: Returns the Boolean value or null if it can't be converted.
* **asInt()**: Returns the Integer value or null if it can't be converted.
* **asDouble()**: Returns the Double value or null if it can't be converted.
* **asString()**: Returns the String value or null if it can't be converted.
* **asDate()**: Returns the Date value or null if it can't be converted. This must be a NumericDate (Unix Epoch/Timestamp). Note that the [JWT Standard](https://tools.ietf.org/html/rfc7519#section-2) specified that all the *NumericDate* values must be in seconds.

#### Collections
To obtain a Claim as a Collection you'll need to provide the **Class Type** of the contents to convert from.

* **asArray(class)**: Returns the value parsed as an Array of elements of type **Class Type**, or null if the value isn't a JSON Array.
* **asList(class)**: Returns the value parsed as a List of elements of type **Class Type**, or null if the value isn't a JSON Array.

If the values inside the JSON Array can't be converted to the given **Class Type**, a `JWTDecodeException` will raise.



## What is Auth0?

Auth0 helps you to:

* Add authentication with [multiple authentication sources](https://docs.auth0.com/identityproviders), either social like **Google, Facebook, Microsoft Account, LinkedIn, GitHub, Twitter, Box, Salesforce, among others**, or enterprise identity systems like **Windows Azure AD, Google Apps, Active Directory, ADFS or any SAML Identity Provider**.
* Add authentication through more traditional **[username/password databases](https://docs.auth0.com/mysql-connection-tutorial)**.
* Add support for **[linking different user accounts](https://docs.auth0.com/link-accounts)** with the same user.
* Support for generating signed [Json Web Tokens](https://docs.auth0.com/jwt) to call your APIs and **flow the user identity** securely.
* Analytics of how, when and where users are logging in.
* Pull data from other sources and add it to the user profile, through [JavaScript rules](https://docs.auth0.com/rules).

## Create a free account in Auth0

1. Go to [Auth0](https://auth0.com) and click Sign Up.
2. Use Google, GitHub or Microsoft Account to login.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for more info.
