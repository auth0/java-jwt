package com.auth0.jwt.pem;

import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


/**
 * X.509 certificate utilities.
 */
public class X509CertUtils {

    private static final String PEM_BEGIN_MARKER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_END_MARKER = "-----END CERTIFICATE-----";

    /**
     * Parses a DER-encoded X.509 certificate.
     */
    public static X509Certificate parse(final byte[] derEncodedCert) {
        if (derEncodedCert == null || derEncodedCert.length == 0) {
            return null;
        }
        try {
            final CertificateFactory cf = CertificateFactory.getInstance("X.509");
            final Certificate cert = cf.generateCertificate(new ByteArrayInputStream(derEncodedCert));
            if (!(cert instanceof X509Certificate)) {
                return null;
            }
            return (X509Certificate) cert;
        } catch (CertificateException e) {
            return null;
        }
    }

    /**
     * Parses a PEM-encoded X.509 certificate.
     */
    public static X509Certificate parse(final String pemEncodedCert) {
        if (pemEncodedCert == null || pemEncodedCert.isEmpty()) {
            return null;
        }
        final int markerStart = pemEncodedCert.indexOf(PEM_BEGIN_MARKER);
        if (markerStart < 0) {
            return null;
        }
        String buf = pemEncodedCert.substring(markerStart + PEM_BEGIN_MARKER.length());
        final int markerEnd = buf.indexOf(PEM_END_MARKER);
        if (markerEnd < 0) {
            return null;
        }
        buf = buf.substring(0, markerEnd);
        buf = buf.replaceAll("\\s", "");
        return parse(new Base64(true).decodeBase64(buf));
    }

}

