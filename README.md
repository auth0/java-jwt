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
    <version>1.0.0</version>
</dependency>
```

### Credits

Most of the code have been written by Luis Faja <https://bitbucket.org/lluisfaja/javajwt>. We just wrapped it in a nicer interface and published it to Maven Central. We'll be adding support for signing and other algorithms in the future.

### FAQ


#### Why another JSON Web Token implementation for Java?
We think that current JWT implementations are either too complex or not tested enough. We want something simple with the right number of abstractions.

## License

The MIT License (MIT)

Copyright (c) 2014 Auth0, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
