# Change Log

## [3.5.0](https://github.com/auth0/java-jwt/tree/3.5.0) (2019-01-03)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.4.1...3.5.0)

**Added**
- Verify a DecodedJWT  [\#308](https://github.com/auth0/java-jwt/pull/308) ([martinoconnor](https://github.com/martinoconnor))

**Changed**
- Add an interface for JWTVerifier. [\#205](https://github.com/auth0/java-jwt/pull/205) ([jebbench](https://github.com/jebbench))

**Fixed**
- Remove unnecessary cast between long/double and floor call [\#296](https://github.com/auth0/java-jwt/pull/296) ([jhorstmann](https://github.com/jhorstmann))

**Security**
- Bump jackson-databind to patch security issues [\#309](https://github.com/auth0/java-jwt/pull/309) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.4.1](https://github.com/auth0/java-jwt/tree/3.4.1) (2018-10-24)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.4.0...3.4.1)

**Security**
- Update jackson-databind dependency [\#292](https://github.com/auth0/java-jwt/pull/292) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.4.0](https://github.com/auth0/java-jwt/tree/3.4.0) (2018-06-13)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.3.0...3.4.0)

**Changed**
- Fix for issue #236 - refactored HMACAlgorithm so that it doesn't throw an UnsupportedEncodingException [\#242](https://github.com/auth0/java-jwt/pull/242) ([obecker](https://github.com/obecker))
- Throw JWTDecodeException when date claim format is invalid [\#241](https://github.com/auth0/java-jwt/pull/241) ([lbalmaceda](https://github.com/lbalmaceda))

**Security**
- Bump Jackson dependency [\#244](https://github.com/auth0/java-jwt/pull/244) ([skjolber](https://github.com/skjolber))

## [3.3.0](https://github.com/auth0/java-jwt/tree/3.3.0) (2017-11-06)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.2.0...3.3.0)
**Closed issues**
- Wrong ES256 signature length [\#187](https://github.com/auth0/java-jwt/issues/187)

**Fixed**
- Rework ECDSA [\#212](https://github.com/auth0/java-jwt/pull/212) ([lbalmaceda](https://github.com/lbalmaceda))
- Instantiate exception only when required [\#198](https://github.com/auth0/java-jwt/pull/198) ([rumdidumdum](https://github.com/rumdidumdum))

## [3.2.0](https://github.com/auth0/java-jwt/tree/3.2.0) (2017-05-04)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.1.0...3.2.0)
**Closed issues**
- Claim.isNull() returns true for JSON Object constructed claims [\#160](https://github.com/auth0/java-jwt/issues/160)
- Incorrectly rejects whitespace after JSON header as invalid [\#144](https://github.com/auth0/java-jwt/issues/144)
- No token type [\#136](https://github.com/auth0/java-jwt/issues/136)
- Timestamps are limited by Integer/int to 2038-01-19T04:14:07.000+0100 [\#132](https://github.com/auth0/java-jwt/issues/132)

**Added**
- Refactor KeyProvider to receive the "Key Id" [\#167](https://github.com/auth0/java-jwt/pull/167) ([lbalmaceda](https://github.com/lbalmaceda))
- Add Sign/Verify of Long type claims [\#157](https://github.com/auth0/java-jwt/pull/157) ([vrancic](https://github.com/vrancic))
- added date validation dedicated exception [\#155](https://github.com/auth0/java-jwt/pull/155) ([Spyna](https://github.com/Spyna))
- Allow to get a Claim as Map [\#152](https://github.com/auth0/java-jwt/pull/152) ([lbalmaceda](https://github.com/lbalmaceda))
- Add Algorithm KeyProvider interface [\#149](https://github.com/auth0/java-jwt/pull/149) ([lbalmaceda](https://github.com/lbalmaceda))
- Instantiate RSA/EC Algorithm with both keys [\#147](https://github.com/auth0/java-jwt/pull/147) ([lbalmaceda](https://github.com/lbalmaceda))
- Add Key Id setter and set JWT Type after signing [\#138](https://github.com/auth0/java-jwt/pull/138) ([lbalmaceda](https://github.com/lbalmaceda))

**Changed**
- Change the JWT.decode() return type to DecodedJWT [\#150](https://github.com/auth0/java-jwt/pull/150) ([lbalmaceda](https://github.com/lbalmaceda))

**Fixed**
- Fix Claim.isNull() method for JSON Objects [\#161](https://github.com/auth0/java-jwt/pull/161) ([lbalmaceda](https://github.com/lbalmaceda))
- Accept blanks, new line and carriage returns on JSON [\#151](https://github.com/auth0/java-jwt/pull/151) ([lbalmaceda](https://github.com/lbalmaceda))
- Fix Date value conversion [\#137](https://github.com/auth0/java-jwt/pull/137) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.1.0](https://github.com/auth0/java-jwt/tree/3.1.0) (2017-01-04)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.0.2...3.1.0)

**Added**
- Make Clock customization accessible for verification [\#125](https://github.com/auth0/java-jwt/pull/125) ([lbalmaceda](https://github.com/lbalmaceda))
- Add getter for all the Payload's Claims [\#124](https://github.com/auth0/java-jwt/pull/124) ([lbalmaceda](https://github.com/lbalmaceda))
- Accept Array type on verification and creation. [\#123](https://github.com/auth0/java-jwt/pull/123) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.0.2](https://github.com/auth0/java-jwt/tree/3.0.2) (2016-12-13)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.0.1...3.0.2)

**Fixed**
- Add targetCompatibility to 1.7 [\#121](https://github.com/auth0/java-jwt/pull/121) ([hzalaz](https://github.com/hzalaz))

## [3.0.1](https://github.com/auth0/java-jwt/tree/3.0.0) (2016-12-05)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.0.0...3.0.1)

Update to allow sync with Maven Central

## [3.0.0](https://github.com/auth0/java-jwt/tree/3.0.0) (2016-12-05)

Reimplemented java-jwt to improve API and include more signing algorithms

## Installation

### Maven

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>3.0.0</version>
</dependency>
```

### Gradle

```gradle
compile 'com.auth0:java-jwt:3.0.0'
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
