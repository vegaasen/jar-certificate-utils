package com.vegaasen.sec.certificate.cert;

import com.vegaasen.sec.certificate.abs.UtilsAbstract;
import com.vegaasen.sec.certificate.common.CertificateProperties;
import com.vegaasen.sec.certificate.http.SslHeaders;

import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;
import java.util.logging.Logger;

import static com.vegaasen.sec.certificate.common.CommonErrors.EMPTY;
import static com.vegaasen.sec.certificate.common.CommonErrors.E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED;
import static com.vegaasen.sec.certificate.common.CommonErrors.E_NO_REQUEST_OBJECT_PRESENT;
import static com.vegaasen.sec.certificate.common.CommonErrors.E_NO_SUCH_HEADER;
import static com.vegaasen.sec.certificate.common.CommonErrors.E_UNABLE_TO_RETRIEVE_THUMBPRINT_FROM_CERTIFICATE;
import static com.vegaasen.sec.certificate.common.CommonErrors.NOT_FOUND;

/**
 * <h1>CertificateRequestUtils.java</h1>
 * <p/>
 * <h2>Introduction</h2>
 * <p>
 * Public Certificate Utilities to be used internally @ WIN.
 * </p>
 * <p>
 * All methods requires that a HttpServletRequest is present as parameter. Otherwise all of them will
 * throw IllegalArgumentException.
 * </p>
 * <p>
 * This class contains the most common methods that applications should be of interrest when dealing with the WIN-platform through the HTTPS protocol. All of the methods will be based on the HttpServletRequest object, and will try to find headers. If the required headers are found, the respective methods will try to do something with the content of the given header, and ultimately return some kind of value based on some kind of datatype.
 * </p>
 * If HttpServletRequest is unavail., but you got the certificate,
 * you can use the <code>com.vegaasen.sec.certificate.cert.CertificateUtils</code>
 *
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 * @version 1.0
 * @see java.security.cert.X509Certificate
 * @see com.vegaasen.sec.certificate.cert.CertificateUtils
 * @since 0.1-SNAPSHOT
 */
public final class CertificateRequestUtils extends UtilsAbstract {

    private static final Logger LOGGER;
    private static final SimpleDateFormat DEFAULT_APACHE_FORMAT;
    private static Date DEFAULT_DATE;

    static {
        DateFormat.getDateInstance(DateFormat.FULL, Locale.US);
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd-HH:mm:ss");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        try {
            DEFAULT_DATE = sdf.parse(sdf.format(new Date(0)));
        } catch (ParseException e) {
            e.printStackTrace();
            DEFAULT_DATE = new Date(120);
        }
        LOGGER = Logger.getLogger(CertificateRequestUtils.class.getName());
        DEFAULT_APACHE_FORMAT = new SimpleDateFormat("MMM dd hh:mm:ss yyyy z", Locale.US);
    }

    private CertificateRequestUtils() {
    }

    /**
     * Get the dealerID from the request.
     *
     * @param request type: HttpServletRequest
     * @return -1 if not found or actual dealerId from CN, if found
     */
    public static int getDealerId(final HttpServletRequest request) {
        if (request != null) {
            final String subject = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT);
            if (subject != null && !subject.isEmpty()) {
                try {
                    final int dealerId = CertificateUtils.getDealerId(subject);
                    if (dealerId > NOT_FOUND) {
                        return dealerId;
                    }
                } catch (CertificateException e) {
                    LOGGER.severe(String.format("Unable to find CN value of subject\n{%s}", subject));
                }
            }
        }
        return NOT_FOUND;
    }

    /**
     * Get the DealerName from the request.
     *
     * @param request type: HttpServletRequest
     * @return empty if not found or actual dealerName from CN, if found
     */
    public static String getDealerName(final HttpServletRequest request) {
        if (request != null) {
            final String subject = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT);
            if (subject != null && !subject.isEmpty()) {
                try {
                    final String dealerName = CertificateUtils.getDealerName(subject);
                    if (!dealerName.isEmpty()) {
                        return dealerName;
                    }
                } catch (CertificateException e) {
                    LOGGER.severe(String.format("Unable to find CN value of subject\n{%s}", subject));
                }
            }
        }
        return EMPTY;
    }

    /**
     * Wrapper for original method located at (see @link). This method generates a thumbprint from the supplied certificate.
     * It uses the whole certificate which can be obtained from the request. The request contains some headers that
     * consists of a string of the pem-encoded certificate. This string is converted to x509Certificate, and then
     * generated a valid thumbprint from some of the attributes located on the certificate.
     * <p/>
     * Note: The header might not be configured as a header. Use with caution!
     *
     * @param certificate supplied X509Certificate
     * @param algorithm   The algorithm to use for the thumbprint-generation. Default is SHA-1
     * @return generated thumbprint
     * @link com.vegaasen.sec.certificate.cert.CertificateUtils.getCertificateThumbprint(java.security.cert.X509Certificate)
     */
    public static String getCertificateThumbprint(final X509Certificate certificate, String algorithm) {
        if (certificate != null) {
            if (algorithm == null || algorithm.isEmpty()) {
                algorithm = CertificateProperties.ALG_SHA1;
            }
            try {
                return CertificateUtils.getCertificateThumbprint(certificate, algorithm);
            } catch (Exception e) {
                LOGGER.severe("Unable to get certificate thumbprint.");
            }
        }
        return EMPTY;
    }

    /**
     * Overloads the x509certificate-method. If the pem-certificate-string is the only
     * resource that is available, then this method can be used to generate the thumbprint.
     *
     * @param pem A certificate in PEM-format
     * @return generated thumbprint
     */
    public static String getCertificateThumbprint(final String pem) {
        if (pem != null && !pem.isEmpty()) {
            String algorithm = CertificateProperties.ALG_X_509;
            final X509Certificate certificate = CertificateUtils.getCertificateFromByteArray(
                    CertificateUtils.convertPemToValidSunFormat(pem),
                    algorithm);
            if (certificate != null) {
                algorithm = CertificateProperties.ALG_SHA1;
                return getCertificateThumbprint(certificate, algorithm);
            }
        }
        return EMPTY;
    }

    /**
     * Get certificate thumbprint from request header.
     *
     * @param request httpServletRequest
     * @return String containing the thumbprint
     * @throws CertificateException If there was no header that contains the pem
     */
    public static String getCertificateThumbprint(final HttpServletRequest request) throws CertificateException {
        if (request != null) {
            final String pem = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM);
            if (pem != null && !pem.isEmpty()) {
                return getCertificateThumbprint(pem);
            }
            LOGGER.warning(E_UNABLE_TO_RETRIEVE_THUMBPRINT_FROM_CERTIFICATE);
        }
        return EMPTY;
    }

    /**
     * Get X509Certificate from the request header. This method will try to get the PEM from the header, and then
     * convert it to X509Certificate from that.
     *
     * @param request httpServletRequest
     * @return X509Certificate generated certificate-object
     * @throws CertificateException If there was no header that contains the pem
     */
    public static X509Certificate getCertificate(final HttpServletRequest request) throws
            CertificateException {
        if (request != null) {
            final String pem = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM);
            if (pem != null && !pem.isEmpty()) {
                final X509Certificate cer = (X509Certificate) CertificateUtils.getCertificateFromString(pem, "");
                if (cer != null) {
                    return cer;
                }
                LOGGER.warning(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
            }
            LOGGER.warning(E_NO_SUCH_HEADER);
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return null;
    }

    /**
     * Get Serial Number for the Client Certificate. Tries to fetch the header containing the serialNumber.
     * If that fails, it will try to get the certificate, and from there get the serialNumber
     *
     * @param request httpServletRequest
     * @return the serial number of the requesting request
     */
    public static String getSerialNumber(final HttpServletRequest request) {
        return getSerialNumber(request, false);
    }

    /**
     * @param request   _
     * @param separated _
     * @return _
     */
    public static String getSerialNumber(final HttpServletRequest request, boolean separated) {
        if (request != null) {
            String sn = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_SERIAL_NUMBER);
            if (sn == null || sn.isEmpty()) {
                try {
                    final X509Certificate cer = getCertificate(request);
                    if (null != cer) {
                        sn = cer.getSerialNumber().toString();
                    }
                } catch (CertificateException e) {
                    LOGGER.warning("Unable to get Serial Number");
                }
            }
            return sn != null && !sn.isEmpty() ? (separated) ? CertificateUtils.appendSeparators(sn) : sn : EMPTY;
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return EMPTY;
    }

    /**
     * Get Expire date for a client certificate. Will try to get the expireDate from the certificate.
     * Tries to convert to a Date-object from a string based on the following format:
     * MMM dd hh:mm:ss yyyy z
     *
     * @param request httpServletRequest
     * @return a Date containing the expire-date
     */
    public static Date getExpireDate(final HttpServletRequest request) {
        if (request != null) {
            final String expireDate = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_NOT_AFTER);
            if (expireDate != null && !expireDate.isEmpty()) {
                try {
                    return DEFAULT_APACHE_FORMAT.parse(expireDate);
                } catch (ParseException e) {
                    LOGGER.warning(String.format("Unable to parse date %s", expireDate));
                }
                return new Date();
            }
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return DEFAULT_DATE;
    }

    /**
     * Use this method to verify a client certificate is valid within a supplied time-span
     *
     * @param request httpServletRequest
     * @param days    days until expire
     * @return true==valid|false==not valid
     */
    public static boolean isValidExpirationDate(final HttpServletRequest request, final long days) {
        if (request != null) {
            final Date expireDate = getExpireDate(request);
            return expireDate != null && days > 0 && CertificateUtils.validExpirationDate(expireDate, days);
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return false;
    }

    /**
     * Get the Common Name from the request.
     *
     * @param request httpServletRequest
     * @return CommonName as String
     */
    public static String getCommonName(final HttpServletRequest request) {
        if (request != null) {
            final String commonName;
            try {
                commonName = CertificateUtils.getCommonName(getSubject(request));
                return commonName;
            } catch (CertificateException e) {
                LOGGER.warning("Unable to get CommonName from certificate.");
            }
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return EMPTY;
    }

    /**
     * Get the Subject from the request.
     *
     * @param request httpServletRequest
     * @return Subject as String
     */
    public static String getSubject(final HttpServletRequest request) {
        if (request != null) {
            return SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT);
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return EMPTY;
    }

    /**
     * Get the Subject of the issuer from the request
     *
     * @param request httpServletRequest
     * @return Subject for the issuer as String
     */
    public static String getSubjectIssuer(final HttpServletRequest request) {
        if (request != null) {
            return SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_ISSUER_SUBJECT);
        }
        LOGGER.severe(E_NO_REQUEST_OBJECT_PRESENT);
        return EMPTY;
    }

}
