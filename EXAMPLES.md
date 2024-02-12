# Examples using java-jwt

* [Inspecting a DecodedJWT](#inspecting-a-decodedjwt)
* [DateTime Claim Validation](#datetime-claim-validation)
* [Using custom claims](#using-custom-claims)
* [Using a KeyProvider](#using-a-keyprovider)

## Inspecting a DecodedJWT

The successful verification of a JWT returns a `DecodedJWT`, from which you can obtain its contents.

```java
DecodedJWT jwt = JWT.require(algorithm)
        .build()
        .verify("a.b.c");

// standard claims can be retrieved through first-class methods
String subject = jwt.getSubject();
String aud = jwt.getAudience();
// ...

// custom claims can also be obtained
String customStringClaim = jwt.getClaim("custom-string-claim").asString();
```

When retrieving custom claims, a [Claim](https://javadoc.io/doc/com.auth0/java-jwt/latest/com/auth0/jwt/interfaces/Claim.html) is returned, which can then be used to obtain the value depending on the value's underlying type.

## DateTime Claim Validation

A JWT token may include DateNumber fields that can be used to validate that:

* The token was issued in a past date `"iat" < NOW`
* The token hasn't expired yet `"exp" > NOW`
* The token can already be used. `"nbf" < NOW`

When verifying a JWT, the standard DateTime claims are validated by default. A `JWTVerificationException` is thrown if any of the claim values are invalid.

To specify a **leeway** in which the JWT should still be considered valid, use the `acceptLeeway()` method in the `JWTVerifier` builder and pass a positive seconds value. This applies to every item listed above.

```java
JWTVerifier verifier = JWT.require(algorithm)
    .acceptLeeway(1) // 1 sec for nbf, iat and exp
    .build();
```

You can also specify a custom value for a given DateTime claim and override the default one for only that claim.

```java
JWTVerifier verifier = JWT.require(algorithm)
    .acceptLeeway(1)   //1 sec for nbf and iat
    .acceptExpiresAt(5)   //5 secs for exp
    .build();
```

If you need to test this behavior in your application, cast the `Verification` instance to a `BaseVerification` to gain visibility of the `verification.build()` method that accepts a `java.time.Clock`. e.g.:

```java
BaseVerification verification = (BaseVerification) JWT.require(algorithm)
    .acceptLeeway(1)
    .acceptExpiresAt(5);
private final Clock mockNow = Clock.fixed(Instant.ofEpochSecond(1477592), ZoneId.of("UTC"));    
JWTVerifier verifier = verification.build(clock);
```

## Using custom claims

### JWT creation
A JWT can be built with custom payload and header claims, by using the `withHeader` and `withClaim` methods.

```java
String jwt = JWT.create()
        .withHeader(headerMap)
        .withClaim("string-claim", "string-value")
        .withClaim("number-claim", 42)
        .withClaim("bool-claim", true)
        .withClaim("datetime-claim", Instant.now())
        .sign(algorithm);
```

See the [JavaDoc](https://javadoc.io/doc/com.auth0/java-jwt/latest/com/auth0/jwt/JWTCreator.Builder.html) for all available custom claim methods.

### JWT verification

You can also verify a JWT's custom claims:

```java
JWTVerifier verifier = JWT.require(algorithm)
        .withClaim("number-claim", 123)
        .withClaimPresence("some-claim-that-just-needs-to-be-present")
        .withClaim("predicate-claim", (claim, decodedJWT) -> "custom value".equals(claim.asString()))
        .build();
DecodedJWT jwt = verifier.verify("my.jwt.token");
```

See the [JavaDoc](https://javadoc.io/doc/com.auth0/java-jwt/latest/com/auth0/jwt/JWTVerifier.BaseVerification.html) for all available custom claim verification methods.

## Using a KeyProvider

A `KeyProvider` can be used to obtain the keys needed for signing and verifying a JWT. How these keys are constructed are beyond the scope of this library, but the [jwks-rsa-java](https://github.com/auth0/jwks-rsa-java) library provides the ability to obtain the public key from a JWK.
The example below demonstrates this for the RSA algorithm (`ECDSAKeyProvider` can be used for ECDSA).

When using RSA or ECDSA algorithms and you just need to **sign** JWTs you can avoid specifying a Public Key by returning a `null` value in `getPublicKeyById` in `KeyProvider` implementation.

The same can be done with the Private Key when you just need to **verify** JWTs by returning a `null` value in `getPrivateKey` and `getPrivateKeyId` in `KeyProvider` implementation.

```java
JwkProvider provider = new JwkProviderBuilder("https://samples.auth0.com/")
        .cached(10, 24, TimeUnit.HOURS)
        .rateLimited(10, 1, TimeUnit.MINUTES)
        .build();
final RSAPrivateKey privateKey = // private key
final String privateKeyId = // private key ID

RSAKeyProvider keyProvider = new RSAKeyProvider() {
    @Override
    public RSAPublicKey getPublicKeyById(String kid) {
        // return null if key is used only for signing.
        return (RSAPublicKey) provider.get(kid).getPublicKey();
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        // return the private key used or null if key is used only for verification.
        return rsaPrivateKey;
    }

    @Override
    public String getPrivateKeyId() {
        // return id of the private key used or null if key is used only for verification.
        return rsaPrivateKeyId;
    }
};

Algorithm algorithm = Algorithm.RSA256(keyProvider);
//Use the Algorithm to create and verify JWTs.
```
