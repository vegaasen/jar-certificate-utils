package com.vegaasen.sec.certificate.common;

public final class CertificateProperties {
    public final static String DEALER_ID = "dealerId";

    public final static String
            ALG_MD5 = "MD5",
            ALG_SHA1 = "SHA";

    public static final String
            ALG_X_509 = "X509",
            ALG_SHA_256 = "SHA-256";

    public static final String
            SUBJECT_SEPARATOR = ", ",
            EQ = "=",
            PROTOL_IDENT = "://";

    public static final int
            T_MILLIS = 1000,
            T_SECOND = 60,
            T_MINUTE = 60,
            T_HOUR = 24,
            T_WEEK = 7,
            T_MONTH = 4, //should have used Double..
            T_YEAR = 52;

    public static final String
            JAVA_SERVLET_REQUEST_X509_CERTIFICATE = "java.servlet.request.X509Certificate";

    public static final String
            RXP_URL_VALIDATION = "\\b(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]";

    private CertificateProperties() {
    }
}
