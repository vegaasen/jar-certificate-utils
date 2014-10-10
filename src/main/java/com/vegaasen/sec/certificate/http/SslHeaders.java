package com.vegaasen.sec.certificate.http;

import com.vegaasen.sec.certificate.common.CommonErrors;
import com.vegaasen.sec.certificate.http.model.SslHeader;

import javax.servlet.http.HttpServletRequest;
import java.util.Enumeration;
import java.util.logging.Logger;

/**
 * List of all possible apache https-headers that _can_ be provided
 * by http-headers between the proxy-servers and the backend-servers
 *
 * @author vegaasen
 * @since 1.0-SNAPSHOT
 */
public final class SslHeaders {

    private static final Logger LOGGER = Logger.getLogger(SslHeaders.class.getName());

    public static String getHeader(final HttpServletRequest request, final CertificateHeader certificateHeader) {
        if (certificateHeader != null && certificateHeader != CertificateHeader.INVALID_HEADER) {
            if (verifyHeaderIsPresentOnRequest(request, certificateHeader)) {
                return request.getHeader(certificateHeader.toString());
            }
            return "";
        }
        throw new IllegalArgumentException("Cannot process null-elements, nor INVALID_HEADER-elements.");
    }

    /**
     * Get a SslHeader-object that contains information regarding the request. All SSL-related request-strings
     * will be placed in that object. The object got getters! :-)
     *
     * @param request - standard http request
     * @return sslHeader
     * @throws IllegalArgumentException _
     */
    public static SslHeader getSSLHeaderFromRequest(final HttpServletRequest request)
            throws IllegalArgumentException {
        if (request != null && request.getHeaderNames() != null) {
            SslHeader header = new SslHeader();
            for (Enumeration enumeration = request.getHeaderNames(); enumeration.hasMoreElements(); ) {
                String headerTitle = (String) enumeration.nextElement();
                CertificateHeader ch = getCertificateHeader(headerTitle);
                if (ch != CertificateHeader.INVALID_HEADER) {
                    switch (ch) {
                        case SSL_CLIENTCERT_PEM:
                            header.setSsl_ClientCert_PEM(request.getHeader(headerTitle));
                            break;
                        case SSL_CLIENTCERT_FINGERPRINT:
                            header.setSsl_ClientCert_Fingerprint(request.getHeader(headerTitle));
                            break;
                        case SSL_CLIENTCERT_SERIAL_NUMBER:
                            header.setSsl_ClientCert_Serial_Number(request.getHeader(headerTitle));
                            break;
                        case SSL_CLIENTCERT_SUBJECT:
                            header.setSsl_ClientCert_Subject(request.getHeader(headerTitle));
                            break;
                        case SSL_CLIENTCERT_ISSUER_SUBJECT:
                            header.setSsl_ClientCert_Issuer_Subject(request.getHeader(headerTitle));
                            break;
                        case SSL_CLIENTCERT_NOT_BEFORE:
                            header.setSsl_ClientCert_Not_Before(request.getHeader(headerTitle));
                            break;
                        case SSL_CLIENTCERT_NOT_AFTER:
                            header.setSsl_ClientCert_Not_After(request.getHeader(headerTitle));
                            break;
                        default:
                            break;
                    }
                }
            }
            return header;
        }
        LOGGER.warning("Unable to process. No request/headers found.");
        throw new IllegalArgumentException("Parameter (request) was null, or it has no headers. Unable to process");
    }

    public static CertificateHeader getCertificateHeader(String identifier) {
        if (identifier != null && !identifier.equals("")) {
            CertificateHeader c = CertificateHeader.fromString(identifier);
            if (!c.equals(CertificateHeader.INVALID_HEADER)) {
                return c;
            }
            LOGGER.fine(String.format("Unable to find a matching header. Skipping %s.", identifier));
        }
        return CertificateHeader.INVALID_HEADER;
    }

    private static boolean verifyHeaderIsPresentOnRequest(final HttpServletRequest request, final CertificateHeader certificateHeader) {
        if (request != null) {
            if (request.getHeader(certificateHeader.toString()) != null) {
                return true;
            }
            LOGGER.fine((String.format(CommonErrors.E_HEADER_ELEMENT_NOT_PRESENT, certificateHeader.toString())));
        }
        return false;
    }


    /**
     * clientCert-PEM
     * clientCert-Subject +
     * -Issuer-Subject (clientCert-Issuer)
     * clientCert-Serial-Number
     * clientCert-Fingerprint
     * clientCert-Not-Before
     * clientCert-Not-After
     * <p/>
     * prefix; clientCert-
     * <p/>
     * todo: apache; request - logger skal ikke ha headere, de skal bruke greiene direkte..
     */

    public enum CertificateHeader {
        SSL_CLIENTCERT_PEM("clientCert-PEM"),
        SSL_CLIENTCERT_SUBJECT("clientCert-Subject"),
        SSL_CLIENTCERT_ISSUER_SUBJECT("clientCert-Issuer-Subject"),
        SSL_CLIENTCERT_SERIAL_NUMBER("clientCert-Serial-Number"),
        SSL_CLIENTCERT_FINGERPRINT("clientCert-Fingerprint"),
        SSL_CLIENTCERT_NOT_BEFORE("clientCert-Not-Before"),
        SSL_CLIENTCERT_NOT_AFTER("clientCert-Not-After"),
        INVALID_HEADER("invalid-Header");

        private String header;

        CertificateHeader(String header) {
            this.header = header;
        }

        @Override
        public String toString() {
            return header;
        }

        public static CertificateHeader fromString(final String header) {
            if (header != null && !header.isEmpty()) {
                for (CertificateHeader h : CertificateHeader.values()) {
                    if (h.header.equals(header)) {
                        return h;
                    }
                }
            }
            return INVALID_HEADER;
        }

    }
}
