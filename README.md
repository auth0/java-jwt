# Java JWT

An implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) developed against `draft-ietf-oauth-json-web-token-08`.

### Usage
Note for Auth0 users:
By default, Auth0's CLIENT_SECRET is base64-encoded.
To work with JWTVerifier or JWTSigner, it must be decoded first.

#### Verify a JWT Token

```java
public class Application {
    public static void main (String [] args) {
        try {
            Base64 decoder = new Base64(true);
            byte[] secret = decoder.decodeBase64(CLIENT_SECRET);
            Map<String,Object> decodedPayload =
                new JWTVerifier(secret, "audience").verify("my-token");

            // Get custom fields from decoded Payload
            System.out.println(decodedPayload.get("name"));
        } catch (SignatureException signatureException) {
            System.err.println("Invalid signature!");
        } catch (IllegalStateException illegalStateException) {
            System.err.println("Invalid Token! " + illegalStateException);
        }
    }
}
```

#### Create a JWT Token

```java
public class Application {
    public static void main (String [] args) {

        Base64 decoder = new Base64(true);
        byte[] secret = decoder.decodeBase64(CLIENT_SECRET);
        JWTSigner jwtSigner = new JWTSigner(secret);
        Map<String, Object> claims = new HashMap<>();
        claims.put("aud", CLIENT_KEY);

        Map<String, Object> actions = new HashMap<>();
        // Customize your scopes/actions with https://auth0.com/docs/api/v2/tokens
        String[] actionsList = {"create", "read"};
        actions.put("actions", actionsList);

        Map<String, Object> users = new HashMap<>();
        users.put("users", actions);

        claims.put("scopes", users);
        claims.put("iat", System.currentTimeMillis());
        claims.put("jti", UUID.randomUUID().toString());

        // Sign and get a Java JWT
        System.out.println(jwtSigner.sign(claims));
    }
}
```

#### Maven coordinates?

Yes, here you are:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>2.1.0</version>
</dependency>
```

### Credits

Most of the code have been written by Luis Faja <https://bitbucket.org/lluisfaja/javajwt>. We just wrapped it in a nicer interface and published it to Maven Central. We'll be adding support for signing and other algorithms in the future.

### Why another JSON Web Token implementation for Java?
We think that current JWT implementations are either too complex or not tested enough. We want something simple with the right number of abstractions.

## Issue Reporting

If you have found a bug or if you have a feature request, please report them at this repository issues section. Please do not report security vulnerabilities on the public GitHub issue tracker. The [Responsible Disclosure Program](https://auth0.com/whitehat) details the procedure for disclosing security issues.

## Author

[Auth0](auth0.com)

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE.txt) file for more info.
