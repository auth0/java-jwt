# Change Log

## [3.18.2](https://github.com/auth0/java-jwt/tree/3.18.2) (2021-09-16)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.18.1...3.18.2)

**Fixed**
- [SDK-2758] Restore withIssuer [\#513](https://github.com/auth0/java-jwt/pull/513) ([jimmyjames](https://github.com/jimmyjames))
- [SDK-2751] Serialize audience claim when a List [\#512](https://github.com/auth0/java-jwt/pull/512) ([jimmyjames](https://github.com/jimmyjames))

## [3.18.1](https://github.com/auth0/java-jwt/tree/3.18.1) (2021-07-06)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.18.0...3.18.1)

**Fixed**
- Fix min JDK version regression [\#504](https://github.com/auth0/java-jwt/pull/504) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.18.0](https://github.com/auth0/java-jwt/tree/3.18.0) (2021-07-05)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.17.0...3.18.0)

**Changed**
- Update OSS release plugin version [\#501](https://github.com/auth0/java-jwt/pull/501) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.17.0](https://github.com/auth0/java-jwt/tree/3.17.0) (2021-06-25)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.16.0...3.17.0)

**Added**
- Add module system support [\#484](https://github.com/auth0/java-jwt/pull/484) ([XakepSDK](https://github.com/XakepSDK))

## [3.16.0](https://github.com/auth0/java-jwt/tree/3.16.0) (2021-05-10)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.15.0...3.16.0)

**Changed**
- Improve Javadoc generation [\#496](https://github.com/auth0/java-jwt/pull/496) ([Marcono1234](https://github.com/Marcono1234))
- Add package-info.java for internal `impl` package [\#495](https://github.com/auth0/java-jwt/pull/495) ([Marcono1234](https://github.com/Marcono1234))

## [3.15.0](https://github.com/auth0/java-jwt/tree/3.15.0) (2021-04-05)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.14.0...3.15.0)

**Changed**
- Remove jcenter [\#482](https://github.com/auth0/java-jwt/pull/482) ([jimmyjames](https://github.com/jimmyjames))
- Move form commons-codec Base64 to j.u.Base64 [\#478](https://github.com/auth0/java-jwt/pull/478) ([XakepSDK](https://github.com/XakepSDK))

## [3.14.0](https://github.com/auth0/java-jwt/tree/3.14.0) (2021-02-26)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.13.0...3.14.0)

**Added**
- Add withPayload to JWTCreator.Builder [\#475](https://github.com/auth0/java-jwt/pull/475) ([jimmyjames](https://github.com/jimmyjames))

## [3.13.0](https://github.com/auth0/java-jwt/tree/3.13.0) (2021-02-05)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.12.1...3.13.0)

**Added**
- Add ability to verify audience contains at least one of those expected [\#472](https://github.com/auth0/java-jwt/pull/472) ([jimmyjames](https://github.com/jimmyjames))
- Add toString to Claim objects [SDK-2225] [\#469](https://github.com/auth0/java-jwt/pull/469) ([jimmyjames](https://github.com/jimmyjames))

## [3.12.1](https://github.com/auth0/java-jwt/tree/3.12.1) (2021-01-20)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.12.0...3.12.1)

**Changed**
- Update jackson-databind to 2.11.0 [\#464](https://github.com/auth0/java-jwt/pull/464) ([darveshsingh](https://github.com/darveshsingh))

## [3.12.0](https://github.com/auth0/java-jwt/tree/3.12.0) (2020-12-18)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.11.0...3.12.0)

**Changed**
- Thread-safe classes should be Shared statically [\#462](https://github.com/auth0/java-jwt/pull/462) ([LeeHainie](https://github.com/LeeHainie))

**Security**
- Update jackson-databind to 2.10.5.1 (fixes CVE-2020-25649) [\#463](https://github.com/auth0/java-jwt/pull/463) ([overheadhunter](https://github.com/overheadhunter))

**Breaking changes**
- Target Java 8 [\#455](https://github.com/auth0/java-jwt/pull/455) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.11.0](https://github.com/auth0/java-jwt/tree/3.11.0) (2020-09-25)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.10.3...3.11.0)

**Added**
- Add ability to verify claim presence [\#442](https://github.com/auth0/java-jwt/pull/442) ([jimmyjames](https://github.com/jimmyjames))
- Add Support for secp256k1 algorithms (AKA ES256K) [\#439](https://github.com/auth0/java-jwt/pull/439) ([jimmyjames](https://github.com/jimmyjames))

**Fixed**
- Fix and document thread-safety [\#427](https://github.com/auth0/java-jwt/pull/427) ([lbalmaceda](https://github.com/lbalmaceda))
- Wrap IllegalArgumentException into JWTDecodeException [\#426](https://github.com/auth0/java-jwt/pull/426) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.10.3](https://github.com/auth0/java-jwt/tree/3.10.3) (2020-04-24)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.10.2...3.10.3)

**Fixed**
- Fixed an NPE on null map and list claims [\#417](https://github.com/auth0/java-jwt/pull/417) ([Vorotyntsev](https://github.com/Vorotyntsev))

## [3.10.2](https://github.com/auth0/java-jwt/tree/3.10.2) (2020-03-27)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.10.1...3.10.2)

**Fixed**
- JavaDoc fix [\#413](https://github.com/auth0/java-jwt/pull/413) ([jimmyjames](https://github.com/jimmyjames))
- Check varargs null values in JWTVerifier [\#412](https://github.com/auth0/java-jwt/pull/412) ([jimmyjames](https://github.com/jimmyjames))

## [3.10.1](https://github.com/auth0/java-jwt/tree/3.10.1) (2020-03-13)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.10.0...3.10.1)

**Changed**
- Update Jackson and Commons Codec dependencies [\#407](https://github.com/auth0/java-jwt/pull/407) ([jimmyjames](https://github.com/jimmyjames))

**Security**
- Update jackson-databind to 2.10.2 [\#399](https://github.com/auth0/java-jwt/pull/399) ([gexclaude](https://github.com/gexclaude))

## [3.10.0](https://github.com/auth0/java-jwt/tree/3.10.0) (2020-02-14)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.9.0...3.10.0)
**Closed issues**
- NullPointerException when the claim doesn't exist in the token [\#384](https://github.com/auth0/java-jwt/issues/384)

**Added**
- Add Javadoc URL and badge to the README [\#382](https://github.com/auth0/java-jwt/pull/382) ([lbalmaceda](https://github.com/lbalmaceda))
- Allow to customize the typ header claim [\#381](https://github.com/auth0/java-jwt/pull/381) ([lbalmaceda](https://github.com/lbalmaceda))
- JWTCreator for basic types [\#282](https://github.com/auth0/java-jwt/pull/282) ([skjolber](https://github.com/skjolber))
- Support verification of Long[] datatype like in JWTCreator [\#278](https://github.com/auth0/java-jwt/pull/278) ([skjolber](https://github.com/skjolber))

**Changed**
- Update to Gradle 6.1.1 [\#389](https://github.com/auth0/java-jwt/pull/389) ([jimmyjames](https://github.com/jimmyjames))

**Fixed**
- Handle missing expected array claim [\#393](https://github.com/auth0/java-jwt/pull/393) ([lbalmaceda](https://github.com/lbalmaceda))
- Update tests to use valid Base64 URL-encoded tokens [\#386](https://github.com/auth0/java-jwt/pull/386) ([jimmyjames](https://github.com/jimmyjames))

## [3.9.0](https://github.com/auth0/java-jwt/tree/3.9.0) (2020-01-02)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.8.3...3.9.0)

**Added**
- Support serialization of DecodedJWT [\#370](https://github.com/auth0/java-jwt/pull/370) ([jimmyjames](https://github.com/jimmyjames))

**Fixed**
- Fixing JwtCreator builder when setting headers as a map [\#320](https://github.com/auth0/java-jwt/pull/320) ([maxbalan](https://github.com/maxbalan))

## [3.8.3](https://github.com/auth0/java-jwt/tree/3.8.3) (2019-09-25)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.8.2...3.8.3)

**Security**
- Fix: updated jackson-databind to 2.10.0.pr3 to block CVE [\#356](https://github.com/auth0/java-jwt/pull/356) ([danbrodsky](https://github.com/danbrodsky))

## [3.8.2](https://github.com/auth0/java-jwt/tree/3.8.2) (2019-08-15)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.8.1...3.8.2)

**Security**
- Fix: updated jackson-databind to 2.9.9.3 to block CVE [\#347](https://github.com/auth0/java-jwt/pull/347) ([danbrodsky](https://github.com/danbrodsky))

## [3.8.1](https://github.com/auth0/java-jwt/tree/3.8.1) (2019-05-22)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.8.0...3.8.1)

**Security**
- Bump dependencies and fix security issue [\#337](https://github.com/auth0/java-jwt/pull/337) ([lbalmaceda](https://github.com/lbalmaceda))

## [3.8.0](https://github.com/auth0/java-jwt/tree/3.8.0) (2019-03-14)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.7.0...3.8.0)

**Added**
- Support multiple issuers #246 [\#288](https://github.com/auth0/java-jwt/pull/288) ([itdevelopmentapps](https://github.com/itdevelopmentapps))

## [3.7.0](https://github.com/auth0/java-jwt/tree/3.7.0) (2019-01-29)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.6.0...3.7.0)

**Added**
- Performance improvements [\#255](https://github.com/auth0/java-jwt/pull/255) ([skjolber](https://github.com/skjolber))

## [3.6.0](https://github.com/auth0/java-jwt/tree/3.6.0) (2019-01-24)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.5.0...3.6.0)

**Added**
- Allow to skip "issued at" validation [\#297](https://github.com/auth0/java-jwt/pull/297) ([complanboy2](https://github.com/complanboy2))

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

**Breaking Changes**
- Fix for [\#236](https://github.com/auth0/java-jwt/pull/236) - refactored HMACAlgorithm so that it doesn't throw an UnsupportedEncodingException [\#242](https://github.com/auth0/java-jwt/pull/242) ([obecker](https://github.com/obecker)). 

Clients using the following methods may need to update their code to not catch an `UnsupportedEncodingException`:
- `public static Algorithm HMAC384(String secret)`
- `public static Algorithm HMAC256(String secret)`
- `public static Algorithm HMAC512(String secret)`

**Changed**
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
