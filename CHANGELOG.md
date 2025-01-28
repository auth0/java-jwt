# Change Log

## [4.5.0](https://github.com/auth0/java-jwt/tree/4.5.0) (2025-01-28)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.4.0...4.5.0)

**Added**
- Upgraded Plugin [\#711](https://github.com/auth0/java-jwt/pull/711) ([tanya732](https://github.com/tanya732))
- Fix jackson vuln [\#705](https://github.com/auth0/java-jwt/pull/705) ([tanya732](https://github.com/tanya732))
- Fix typo in example code [\#682](https://github.com/auth0/java-jwt/pull/682) ([kasperkarlsson](https://github.com/kasperkarlsson))
- Remove dead README links [\#676](https://github.com/auth0/java-jwt/pull/676) ([jimmyjames](https://github.com/jimmyjames))
- Fix typo on a comment in JWTCreator.java [\#672](https://github.com/auth0/java-jwt/pull/672) ([sgc109](https://github.com/sgc109))
- Remove CircleCI [\#670](https://github.com/auth0/java-jwt/pull/670) ([jimmyjames](https://github.com/jimmyjames))
- Empty string audience claim should be deserialized as empty string [\#663](https://github.com/auth0/java-jwt/pull/663) ([jimmyjames](https://github.com/jimmyjames))

**Fixed**
- empty expected audience array should throw InvalidClaimException [\#679](https://github.com/auth0/java-jwt/pull/679) ([jimmyjames](https://github.com/jimmyjames))

## [4.5.0](https://github.com/auth0/java-jwt/tree/4.5.0) (2025-01-22)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.4.0...4.5.0)

**Added**
- Fix jackson vuln [\#705](https://github.com/auth0/java-jwt/pull/705) ([tanya732](https://github.com/tanya732))
- Fix typo in example code [\#682](https://github.com/auth0/java-jwt/pull/682) ([kasperkarlsson](https://github.com/kasperkarlsson))
- Remove dead README links [\#676](https://github.com/auth0/java-jwt/pull/676) ([jimmyjames](https://github.com/jimmyjames))
- Fix typo on a comment in JWTCreator.java [\#672](https://github.com/auth0/java-jwt/pull/672) ([sgc109](https://github.com/sgc109))
- Remove CircleCI [\#670](https://github.com/auth0/java-jwt/pull/670) ([jimmyjames](https://github.com/jimmyjames))
- Empty string audience claim should be deserialized as empty string [\#663](https://github.com/auth0/java-jwt/pull/663) ([jimmyjames](https://github.com/jimmyjames))

**Fixed**
- empty expected audience array should throw InvalidClaimException [\#679](https://github.com/auth0/java-jwt/pull/679) ([jimmyjames](https://github.com/jimmyjames))

## [4.4.0](https://github.com/auth0/java-jwt/tree/4.4.0) (2023-03-31)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.3.0...4.4.0)

**Changed**
- Add support for passing json values for header and payload [\#643](https://github.com/auth0/java-jwt/pull/643) ([andrewrigas](https://github.com/andrewrigas))
- Preserve insertion order for claims [\#656](https://github.com/auth0/java-jwt/pull/656) ([snago](https://github.com/snago))
- Update Jackson to 2.14.2 [\#657](https://github.com/auth0/java-jwt/pull/657) ([jimmyjames](https://github.com/jimmyjames))

## [4.3.0](https://github.com/auth0/java-jwt/tree/4.3.0) (2023-02-10)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.2.2...4.3.0)

**Changed**
- Improve JWT parse/decode performance [\#620](https://github.com/auth0/java-jwt/pull/620) ([noetro](https://github.com/noetro))

**Fixed**
- Fix for exp claim considered valid if equal to now [\#652](https://github.com/auth0/java-jwt/pull/652) ([jimmyjames](https://github.com/jimmyjames))
- Code cleanup [\#642](https://github.com/auth0/java-jwt/pull/642) ([CodeDead](https://github.com/CodeDead))

## [4.2.2](https://github.com/auth0/java-jwt/tree/4.2.2) (2023-01-11)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.2.1...4.2.2)

This patch release does not contain any functional changes, but is being released using an updated signing key for verification as part of our commitment to best security practices.
Please review [the README note for additional details.](https://github.com/auth0/java-jwt/blob/master/README.md)

## [4.2.1](https://github.com/auth0/java-jwt/tree/4.2.1) (2022-10-24)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.2.0...4.2.1)

**Security**
- Use latest ship orb [\#634](https://github.com/auth0/java-jwt/pull/634) ([jimmyjames](https://github.com/jimmyjames))
- Bump `com.fasterxml.jackson.core:jackson-databind` to 2.13.4.2 [\#630](https://github.com/auth0/java-jwt/pull/630) ([evansims](https://github.com/evansims))

## [4.2.0](https://github.com/auth0/java-jwt/tree/4.2.0) (2022-10-19)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.1.0...4.2.0)

**Changed**
- Re-enable japicmp API diff checking [\#619](https://github.com/auth0/java-jwt/pull/619) ([jimmyjames](https://github.com/jimmyjames))
- Update .shiprc to only update lib version in build.gradle [\#625](https://github.com/auth0/java-jwt/pull/625) ([jimmyjames](https://github.com/jimmyjames))
- Optimise TokenUtils parsing [\#611](https://github.com/auth0/java-jwt/pull/611) ([noetro](https://github.com/noetro))
- Update Circle Ship Orb configuration [\#616](https://github.com/auth0/java-jwt/pull/616) ([frederikprijck](https://github.com/frederikprijck))

**Fixed**
- Update Claim#asString documentation [\#615](https://github.com/auth0/java-jwt/pull/615) ([jimmyjames](https://github.com/jimmyjames))

## [4.1.0](https://github.com/auth0/java-jwt/tree/4.1.0) (2022-10-06)
[Full Changelog](https://github.com/auth0/java-jwt/compare/4.0.0...4.1.0)

**⚠️ BREAKING CHANGES**
- Make JWT constants final values [\#604](https://github.com/auth0/java-jwt/pull/604) ([poovamraj](https://github.com/poovamraj))

**Added**
- Add integration with our Shipping orb [\#612](https://github.com/auth0/java-jwt/pull/612) ([frederikprijck](https://github.com/frederikprijck))
- Add Ship CLI support [\#609](https://github.com/auth0/java-jwt/pull/609) ([jimmyjames](https://github.com/jimmyjames))
- Provide straightforward example for JWKS [\#600](https://github.com/auth0/java-jwt/pull/600) ([poovamraj](https://github.com/poovamraj))

**Changed**
- Update to gradle 6.9.2 [\#608](https://github.com/auth0/java-jwt/pull/608) ([jimmyjames](https://github.com/jimmyjames))
- Update OSS plugin to latest [\#607](https://github.com/auth0/java-jwt/pull/607) ([jimmyjames](https://github.com/jimmyjames))
- [SDK-3466] Upgrade Codecov [\#595](https://github.com/auth0/java-jwt/pull/595) ([evansims](https://github.com/evansims))
- Update README.md [\#590](https://github.com/auth0/java-jwt/pull/590) ([poovamraj](https://github.com/poovamraj))

**Fixed**
- Check for null token before splitting [\#606](https://github.com/auth0/java-jwt/pull/606) ([jimmyjames](https://github.com/jimmyjames))
- [SDK-3816] Update docs for verification thread-safety [\#605](https://github.com/auth0/java-jwt/pull/605) ([jimmyjames](https://github.com/jimmyjames))

## [4.0.0](https://github.com/auth0/java-jwt/tree/4.0.0) (2022-06-24)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.19.2...4.0.0)

**This is a major release and contains breaking changes!**

- Check the [Migration Guide](https://github.com/auth0/java-jwt/blob/master/MIGRATION_GUIDE.md) to understand the changes required to migrate your application to v4.

### Main features
- Predicates based claim verification
- Support for Instant API and Lambda functions
- Improved Exceptions API
- Consistent null handling

See the changelog entries for additional details.

## [4.0.0-beta.0](https://github.com/auth0/java-jwt/tree/4.0.0-beta.0) (2022-05-06)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.19.2...4.0.0-beta.0)

💡 Check the [Migration Guide](https://github.com/auth0/java-jwt/blob/master/MIGRATION_GUIDE.md) to understand the changes required to migrate your application to v4.

**Added**
- JavaDoc updated [\#577](https://github.com/auth0/java-jwt/pull/577) ([poovamraj](https://github.com/poovamraj))
- Add Migration Guide [\#576](https://github.com/auth0/java-jwt/pull/576) ([jimmyjames](https://github.com/jimmyjames))
- Expose claim name and header constants [\#574](https://github.com/auth0/java-jwt/pull/574) ([jimmyjames](https://github.com/jimmyjames))
- Added support for multiple checks on a single claim [\#573](https://github.com/auth0/java-jwt/pull/573) ([poovamraj](https://github.com/poovamraj))
- Improved README structure [\#571](https://github.com/auth0/java-jwt/pull/571) ([poovamraj](https://github.com/poovamraj))
- Improved Exception Handling [\#568](https://github.com/auth0/java-jwt/pull/568) ([poovamraj](https://github.com/poovamraj))
- Predicate based Claim verification [\#562](https://github.com/auth0/java-jwt/pull/562) ([poovamraj](https://github.com/poovamraj))
- Add lint checks [\#561](https://github.com/auth0/java-jwt/pull/561) ([poovamraj](https://github.com/poovamraj))
- Support date/time custom claim validation [\#538](https://github.com/auth0/java-jwt/pull/538) ([jimmyjames](https://github.com/jimmyjames))
- Add Instant support [\#537](https://github.com/auth0/java-jwt/pull/537) ([jimmyjames](https://github.com/jimmyjames))
- Testing Java LTS versions [\#536](https://github.com/auth0/java-jwt/pull/536) ([poovamraj](https://github.com/poovamraj))

**Changed**
- Null claim handling [\#564](https://github.com/auth0/java-jwt/pull/564) ([poovamraj](https://github.com/poovamraj))
- Undeprecate Single Key Constructor for Algorithms [\#551](https://github.com/auth0/java-jwt/pull/551) ([poovamraj](https://github.com/poovamraj))
- Update documentation and undeprecate single content sign methods [\#550](https://github.com/auth0/java-jwt/pull/550) ([poovamraj](https://github.com/poovamraj))
- Update test deps [\#539](https://github.com/auth0/java-jwt/pull/539) ([jimmyjames](https://github.com/jimmyjames))

**Deprecated**
- Deprecate secp256k1 curve for EC Algorithms [\#540](https://github.com/auth0/java-jwt/pull/540) ([poovamraj](https://github.com/poovamraj))

**Removed**
- Remove ES256K support [\#556](https://github.com/auth0/java-jwt/pull/556) ([poovamraj](https://github.com/poovamraj))
- Remove impl package export in module-info [\#553](https://github.com/auth0/java-jwt/pull/553) ([poovamraj](https://github.com/poovamraj))
- Remove internal Clock [\#533](https://github.com/auth0/java-jwt/pull/533) ([jimmyjames](https://github.com/jimmyjames))

**Fixed**
- Improve keyprovider reliability [\#570](https://github.com/auth0/java-jwt/pull/570) ([poovamraj](https://github.com/poovamraj))
- Support date/time custom claim validation [\#538](https://github.com/auth0/java-jwt/pull/538) ([jimmyjames](https://github.com/jimmyjames))
- Test only change - remove unnecessary throws clause from tests [\#535](https://github.com/auth0/java-jwt/pull/535) ([jimmyjames](https://github.com/jimmyjames))

**Security**
- Updated documentation regarding HMAC Key length [\#580](https://github.com/auth0/java-jwt/pull/580) ([poovamraj](https://github.com/poovamraj))

**Breaking changes**
- Added support for multiple checks on a single claim [\#573](https://github.com/auth0/java-jwt/pull/573) ([poovamraj](https://github.com/poovamraj))
- Improve keyprovider reliability [\#570](https://github.com/auth0/java-jwt/pull/570) ([poovamraj](https://github.com/poovamraj))
- Remove ES256K support [\#556](https://github.com/auth0/java-jwt/pull/556) ([poovamraj](https://github.com/poovamraj))
- Remove impl package export in module-info [\#553](https://github.com/auth0/java-jwt/pull/553) ([poovamraj](https://github.com/poovamraj))
- Fix header claims serialization [\#549](https://github.com/auth0/java-jwt/pull/549) ([jimmyjames](https://github.com/jimmyjames))
- Serialize dates in collections as seconds since epoch [\#534](https://github.com/auth0/java-jwt/pull/534) ([jimmyjames](https://github.com/jimmyjames))
- Replace com.auth0.jwt.interfaces.Clock with java.time.Clock [\#532](https://github.com/auth0/java-jwt/pull/532) ([jimmyjames](https://github.com/jimmyjames))

## [3.19.2](https://github.com/auth0/java-jwt/tree/3.19.2) (2022-05-05)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.19.1...3.19.2)

**Security**
- [SDK-3311] Added protection against CVE-2022-21449 [\#579](https://github.com/auth0/java-jwt/pull/579) ([poovamraj](https://github.com/poovamraj))

## [3.19.1](https://github.com/auth0/java-jwt/tree/3.19.1) (2022-03-30)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.19.0...3.19.1)

**Security**
- Security: Bump `jackson-databind` to 2.13.2.2 [\#566](https://github.com/auth0/java-jwt/pull/566) ([evansims](https://github.com/evansims))

## [3.19.0](https://github.com/auth0/java-jwt/tree/3.19.0) (2022-03-14)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.18.3...3.19.0)

**Deprecated**
- Deprecate ES256K Algorithm [\#543](https://github.com/auth0/java-jwt/pull/543) ([poovamraj](https://github.com/poovamraj))

**Fixed**
- fix typos in JWTVerifier#verify docstring [\#526](https://github.com/auth0/java-jwt/pull/526) ([OdunlamiZO](https://github.com/OdunlamiZO))

**Security**
- Bump `jackson-databind` dependency to 2.13.2 [\#542](https://github.com/auth0/java-jwt/pull/542) ([evansims](https://github.com/evansims))

## [3.18.3](https://github.com/auth0/java-jwt/tree/3.18.3) (2022-01-13)
[Full Changelog](https://github.com/auth0/java-jwt/compare/3.18.2...3.18.3)

**Security**
- Update jackson dependency [\#523](https://github.com/auth0/java-jwt/pull/523) ([poovamraj](https://github.com/poovamraj))

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
