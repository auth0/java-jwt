# Java JWT

An implementation of [JSON Web Tokens](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) developed against `draft-ietf-oauth-json-web-token-08`.

### Usage

```java
public class Application {
    public static void main (String [] args) {
        try {
            Map<String,Object> decodedPayload =
                new JWTVerifier("secret", "audience").verify("my-token");
                
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

#### Maven coordinates?

Yes, here you are:

```xml
<dependency>
    <groupId>com.auth0</groupId>
    <artifactId>java-jwt</artifactId>
    <version>2.0.1</version>
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
