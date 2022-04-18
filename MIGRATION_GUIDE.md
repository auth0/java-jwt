# Migration Guide

## Upgrading from v3.x -> v4.0

The version 4 release contains several improvements:

- Support for `java.time.Instant` when creating or verifying JWTs with Numeric Date claim values.
- Improvements to JWT claim validation, including support for custom claim validation using Predicates.
- Improved exception handling when validating JWTs, to better inform of the reason for failed validation.
- Consistent handling of `null` claim values both when creating and validation JWTs.

This guide captures the changes you should be aware of when planning and upgrading to version 4.

### Compile or runtime breaking changes

**Classes or methods removed:**
- The `impl` package has been removed as an export in `module-info.java`. This package contains implementation-specific code that may change at any point.
- Support for the ES256K algorithm has been removed, as it is disabled in Java 15+. The `Algorithm#ECDSA256K(ECDSAKeyProvider keyProvider)` and `Algorithm#ECDSA256K(ECPublicKey publicKey, ECPrivateKey privateKey)` methods have been removed.
- `com.auth0.jwt.interfaces.Clock` has been removed. Instead, an implementation of `java.time.Clock` can be passed to the `BaseVerification` for testing purposes.
- `com.auth0.jwt.impl.NullClaim` has been removed. `Claim#isNull` can be used to determine if a claim's value is `null`.
- `com.auth0.jwt.impl.PublicClaims` was removed, and replaced by `com.auth0.jwt.StandardClaims` and `com.auth0.jwt.HeaderParams`.

### Behavioral potentially breaking changes

#### JWT creation

- All date/time claim values are now serialized as **seconds since the epoch**, in both the payload and header. In version 3, date/time claims nested in a list or map, as well as any header parameters with date/time values, were serialized as milliseconds since the epoch. 
- When creating a JWT, passing `null` as the value no longer removes the claim if it was previously added to the builder. It now adds the claim with a `null` value.

#### JWT validation

- In version 3, specifying multiple claim expectations for the same claim name would override any previous expectations for that claim. In version 4, all expectations for that claim will be validated.
- In version 3, passing `null` for the value of a claim expectation would remove that expectation from the validation. In version 4, passing `null` does not remove that expectation, but instead validates that the claim has the literal value `null`.
- When validating a JWT, if an expected claim is present in the JWT but contains a value different from the one expected, an `IncorrectClaimException` (subclass of `InvalidClaimException`) will now be thrown instead of an `InvalidClaimException`.
- When validating a JWT, if an expected claim is not present in the JWT, an `MissingClaimException` (subclass of `InvalidClaimException`) will now be thrown instead of an `InvalidClaimException`.
- `withClaimPresence(String claimName)` now validates that the claim is present in the JWT, and a claim with a `null` value is considered present. Previously, a claim with a value of `null` would be considered as missing and fail the validation.
- When validating a date/time claim value, the validation no longer checks for strict equality of the claim's value and the provided `Date` (or `Instant`). Instead, the expected `Date` or `Instant` will be compared to the claim's value only considering seconds (because JWT date/time claims are represented as seconds since the epoch).

#### Claim changes

- `com.auth0.jwt.interfaces.Claim#isNull()` now returns true only if the claim is present and its value is `null`. Previously, it returned true if the claim was present and its value was `null`, or if the claim was not present in the JWT. To check if the claim is present or not in the JWT, use `isMissing()`.

### New classes or methods

#### `IncorrectClaimException` added

This class extends `InvalidClaimException` and represents that when validating a JWT, an expected claim exists in the JWT but does not match the expected value.

#### `MissingClaimException` added

This class extends `InvalidClaimException` and represents that when validating a JWT, an expected claim is missing from the JWT.

### `HeaderParams` added

This class contains constants representing common header parameter names.

### `StandardClaims` added

This class contains constants representing the standard claim names.

#### `JWTCreator` new methods

- `JWTCreator.Builder#withExpiresAt(Instant expiresAt)` - adds the `exp` claim to the JWT from a `java.time.Instant`.
- `JWTCreator.Builder#withNotBefore(Instant notBefore)` - adds the `nbf` claim to the JWT from a `java.time.Instant`.
- `JWTCreator.Builder#withIssuedAt(Instant issuedAt)` - adds the `iat` claim to the JWT from a `java.time.Instant`.
- `JWTCreator.Builder#withClaim(String claimName, Instant value)` - adds a claim to the JWT from a `java.time.Instant`.
- `JWTCreator.Builder#withNullClaim(String claimName)` - adds a claim to the JWT with the literal value `null`.

#### `DecodedJWT` new methods

- `Instant getExpiresAtAsInstant()` - Returns a JWT's `exp` claim as a `java.time.Instant`.
- `Instant getNotBeforeAsInstant()` - Returns a JWT's `nbf` claim as a `java.time.Instant`.
- `Instant getIssuedAtAsInstant()` - Returns a JWT's `iat` claim as a `java.time.Instant`.

#### `Claim` new methods

- `Instant asInstant()` - Gets a claim as a `java.time.Instant`.
- `boolean isMissing()` - Returns whether the claim is present or not.

#### `Verification` new methods

- `Verification withClaim(String name, Instant value)` - Adds an expectation that a claim with the provided name has a value equal to the provided `java.time.Instant`.
- `Verification withClaim(String name, BiPredicate<Claim, DecodedJWT> predicate)` - Allows for a claim to be validated with the supplied predicate. 
- `Verification withNullClaim(String name)` - Adds an expectation that a claim with the provided name has a value equal to the literal `null`.
