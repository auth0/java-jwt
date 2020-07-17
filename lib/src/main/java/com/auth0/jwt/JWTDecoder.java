package com.auth0.jwt;

import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.impl.JWTParser;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Header;
import com.auth0.jwt.interfaces.Payload;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * The JWTDecoder class holds the decode method to parse a given JWT token into it's JWT representation.
 * <p>
 * This class is thread-safe.
 */
@SuppressWarnings("WeakerAccess")
final class JWTDecoder implements DecodedJWT, Serializable {

    private static final long serialVersionUID = 1873362438023312895L;

    private final String[] parts;
    private final Header header;
    private final Payload payload;

    JWTDecoder(@NotNull String jwt) throws JWTDecodeException {
        this(new JWTParser(), jwt);
    }

    JWTDecoder(@NotNull JWTParser converter, @NotNull String jwt) throws JWTDecodeException {
        parts = TokenUtils.splitToken(jwt);
        String headerJson;
        String payloadJson;
        try {
            headerJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[0]));
            payloadJson = StringUtils.newStringUtf8(Base64.decodeBase64(parts[1]));
        } catch (NullPointerException e) {
            throw new JWTDecodeException("The UTF-8 Charset isn't initialized.", e);
        } catch (IllegalArgumentException e){
            throw new JWTDecodeException("The input is not a valid base 64 encoded string.", e);
        }
        header = converter.parseHeader(headerJson);
        payload = converter.parsePayload(payloadJson);
    }

    @Nullable
    @Override
    public String getAlgorithm() {
        return header.getAlgorithm();
    }

    @Nullable
    @Override
    public String getType() {
        return header.getType();
    }

    @Nullable
    @Override
    public String getContentType() {
        return header.getContentType();
    }

    @Nullable
    @Override
    public String getKeyId() {
        return header.getKeyId();
    }

    @NotNull
    @Override
    public Claim getHeaderClaim(@NotNull String name) {
        return header.getHeaderClaim(name);
    }

    @Nullable
    @Override
    public String getIssuer() {
        return payload.getIssuer();
    }

    @Nullable
    @Override
    public String getSubject() {
        return payload.getSubject();
    }

    @Nullable
    @Override
    public List<String> getAudience() {
        return payload.getAudience();
    }

    @Nullable
    @Override
    public Date getExpiresAt() {
        return payload.getExpiresAt();
    }

    @Nullable
    @Override
    public Date getNotBefore() {
        return payload.getNotBefore();
    }

    @Nullable
    @Override
    public Date getIssuedAt() {
        return payload.getIssuedAt();
    }

    @Nullable
    @Override
    public String getId() {
        return payload.getId();
    }

    @NotNull
    @Override
    public Claim getClaim(@NotNull String name) {
        return payload.getClaim(name);
    }

    @NotNull
    @Override
    public Map<String, Claim> getClaims() {
        return payload.getClaims();
    }

    @NotNull
    @Override
    public String getHeader() {
        return parts[0];
    }

    @NotNull
    @Override
    public String getPayload() {
        return parts[1];
    }

    @NotNull
    @Override
    public String getSignature() {
        return parts[2];
    }

    @NotNull
    @Override
    public String getToken() {
        return String.format("%s.%s.%s", parts[0], parts[1], parts[2]);
    }
}
