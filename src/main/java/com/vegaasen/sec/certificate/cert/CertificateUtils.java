package com.vegaasen.sec.certificate.cert;

import com.vegaasen.sec.certificate.abs.UtilsAbstract;
import com.vegaasen.sec.certificate.common.CertificateFields;
import com.vegaasen.sec.certificate.http.SslHeaders;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.servlet.http.HttpServletRequest;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.logging.Logger;

import static com.vegaasen.sec.certificate.common.CertificateProperties.*;
import static com.vegaasen.sec.certificate.common.CommonErrors.*;

/**
 * Simple class that provides static methods that is used when needed to collect information from x509-certificates.
 * This class does not provide all methods avail. (like getVersion), as there is already a lot of helper-methods
 * embedded in the original x509-class defined by Sun.
 * <p/>
 * todo: refactor, refactor, refactor
 *
 * @author nissen
 * @version 0.1
 * @see java.security.cert.X509Certificate
 */
public final class CertificateUtils extends UtilsAbstract {

    private static final Logger LOG = Logger.getLogger(CertificateUtils.class.getName());
    private static final String COMMA_DELIMITER = ",";

    public static final String REGEX_NUMERICAL_ONLY = "[^0-9]"; //todo: can also be expert butikk 5.. :-|
    @SuppressWarnings("unused")
    public static final String REGEX_ALPHABETICAL_ONLY = "[^a-zA-Z\\s]"; // todo: butikk 5..! :-| A/s osv.
    public static final String REGEX_VALID_CSR = "not_defined_yet";

    private static final String REGEX_INVALID_SUBJECT_CONTENT = "\\\\";
    private static final String REGEXP_REPLACEMENT_OF_INVALID_SUBJECT = "\\\\\\\\";
    private static final String PORT_IDENTIFIER = ":";
    private static final int
            DEFAULT_TIMEOUT = 10000,
            DEFAULT_HTTPS_PORT = 443,
            DEFAULT_NUMBER_OF_DECIMALS = 1;
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";

    private CertificateUtils() {
    }

    /**
     * Assemble the string used in e.g CosSecurity to match a dealer.
     *
     * @param x509Certificate x509Certificate
     * @param outputEnigma    true=old enigma style | false = Clavis style
     * @return _
     * @throws CertificateException _
     */
    public static String getCosSecurityFormattedString(final X509Certificate x509Certificate, final Boolean outputEnigma)
            throws CertificateException {
        if (isCertificatePresent(x509Certificate)) {
            StringBuilder formattedSubject = new StringBuilder();
            if (outputEnigma == null || !outputEnigma) {
                formattedSubject.append(CertificateFields.COMMON_NAME + EQ);
                formattedSubject.append(getIssuerCommonName_x509(x509Certificate));
                formattedSubject.append(SUBJECT_SEPARATOR);
                final List<String> OUs = getIssuerOrganizationUnit_x509(x509Certificate);
                for (String ou : OUs) {
                    formattedSubject.append(CertificateFields.ORGANIZATION_UNIT + EQ);
                    formattedSubject.append(ou);
                    formattedSubject.append(SUBJECT_SEPARATOR);
                }
                formattedSubject.append(CertificateFields.ORGANIZATION + EQ);
                formattedSubject.append(getIssuerOrganization_x509(x509Certificate));
                formattedSubject.append(SUBJECT_SEPARATOR);
                formattedSubject.append(CertificateFields.COUNTRY + EQ);
                formattedSubject.append(getIssuerCountry_x509(x509Certificate));
                formattedSubject.append(SUBJECT_SEPARATOR);
                formattedSubject.append(DEALER_ID + EQ);
                formattedSubject.append(getDealerId(x509Certificate));
            } else {
                throw new CertificateException("Enigma is no longer supported. Option is deprecated.");
            }
            return formattedSubject.toString();
        }
        return "";
    }

    /**
     * New method that relates to CosSecurity. Generates a string based on Issuer and Thumbprint of certificate
     * This method will on a later stage replace the method <code>getCosSecurityFormattedString()</code>
     *
     * @param x509Certificate certificate to verify
     * @return String based on the certificate and its thumbprint
     * @throws Exception _
     */
    public static String getCosSecurityFormattedStringBasedOnThumbprint(final X509Certificate x509Certificate)
            throws Exception {
        if (isCertificatePresent(x509Certificate)) {
            return getCertificateThumbprint(x509Certificate, "") + SUBJECT_SEPARATOR + DEALER_ID + EQ + getDealerId(x509Certificate);
        }
        throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
    }

    /**
     * @param certificate certificate
     * @param referenceId Use com.vegaasen.sec.certificate.common.CertificateReferences to get a list of the most popular
     *                    reference id's
     * @return byte[] containing the requested extension value
     * @throws CertificateException _
     */
    public static byte[] getExtensionValue(final X509Certificate certificate, final String referenceId)
            throws CertificateException {
        if (referenceId != null && !referenceId.equals("") && isCertificatePresent(certificate)) {
            byte[] extensionValue = certificate.getExtensionValue(referenceId);
            if (extensionValue != null && extensionValue.length > 0) {
                return extensionValue;
            }
            return new byte[]{};
        }
        throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
    }

    /**
     * @param x509Certificate X509Certificate
     * @param days            days from _now_ the certificate
     * @return true if its valid, false if its not valid..
     * @throws CertificateException _
     */
    public static boolean validExpirationDate(final X509Certificate x509Certificate, final long days) throws CertificateException {
        if (days >= 0) {
            if (isCertificatePresent(x509Certificate)) {
                return validExpirationDate(x509Certificate.getNotAfter(), days);
            }
            throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
        }
        throw new IllegalArgumentException("Days is less than 0. Verify input.");
    }

    /**
     * Simple method that checks weather the certificate will expire in n days.
     *
     * @param expireDate Date that expected to expire.
     * @param days       days from _now_ the certificate
     * @return true if its valid, false if its not valid..
     */
    public static boolean validExpirationDate(final Date expireDate, final long days) {
        if (days >= 0) {
            if (expireDate != null) {
                Date today = new Date();
                double daysRemaining = getSpanUntilExpiration(expireDate, today, Unit.DAYS);
                return daysRemaining > days;
            }
            throw new IllegalArgumentException("Date is not specified. Verify input.");
        }
        throw new IllegalArgumentException("Days is less than 0. Verify input.");
    }

    /**
     * Get the number of units until the certificate expires.
     * E.g:
     * Cert expires 14.02.2015
     * Date in comparison: 03.02.2016
     * Results in (with e.g Unit.DAYS):
     *
     * @param x509Certificate x509Certificate
     * @param date            the date to compare
     * @param unit            time-unit (Unit)
     * @return number representing the expiration time (specified with param unit)
     * @throws IllegalArgumentException _
     * @throws CertificateException     _
     */
    public static double getSpanUntilExpiration(final X509Certificate x509Certificate, final Date date, final Unit unit)
            throws IllegalArgumentException, CertificateException {
        if (date != null) {
            if (isCertificatePresent(x509Certificate)) {
                return getSpanUntilExpiration(x509Certificate.getNotAfter(), date, unit);
            }
        }
        throw new IllegalArgumentException("Date is either null or invalid. Verify input.");
    }

    /**
     * Get the number of units until the certificate expires.
     * E.g:
     * Cert expires 14.02.2015
     * Date in comparison: 03.02.2016
     * Results in (with e.g Unit.DAYS)
     *
     * @param expireDate expire date
     * @param date       the date to compare
     * @param unit       time-unit (Unit)
     * @return number representing the expiration time (specified with param unit)
     * @throws IllegalArgumentException _
     */
    public static double getSpanUntilExpiration(final Date expireDate, final Date date, final Unit unit) {
        if (date != null && expireDate != null) {
            final double timeBetween = (expireDate.getTime() - date.getTime());
            switch (unit) {
                case MILLS:
                    return round((timeBetween), DEFAULT_NUMBER_OF_DECIMALS);
                case SECONDS:
                    return round(((timeBetween) / T_MILLIS), DEFAULT_NUMBER_OF_DECIMALS);
                case MINUTES:
                    return round((((timeBetween) / T_MILLIS) / T_SECOND), DEFAULT_NUMBER_OF_DECIMALS);
                case HOURS:
                    return round(((((timeBetween) / T_MILLIS) / T_SECOND) / T_MINUTE), DEFAULT_NUMBER_OF_DECIMALS);
                case DAYS:
                    return round((((((timeBetween) / T_MILLIS) / T_SECOND) / T_MINUTE) / T_HOUR),
                            DEFAULT_NUMBER_OF_DECIMALS);
                case WEEKS:
                    return round(((((((timeBetween) / T_MILLIS) / T_SECOND) / T_MINUTE) / T_HOUR) / T_WEEK),
                            DEFAULT_NUMBER_OF_DECIMALS);
                case MONTHS:
                    return round(((((((timeBetween) / T_MILLIS) / T_SECOND) / T_MINUTE) / T_HOUR) / T_WEEK) / T_MONTH,
                            DEFAULT_NUMBER_OF_DECIMALS);
                case YEARS:
                    return round((((((((timeBetween) / T_MILLIS) / T_SECOND) / T_MINUTE) / T_HOUR) / T_WEEK) / T_YEAR),
                            DEFAULT_NUMBER_OF_DECIMALS);
                default:
                    return (timeBetween);
            }
        }
        throw new IllegalArgumentException("Date or ExpireDate is either null or invalid. Verify input.");
    }

    /**
     * Generate the certificate thumbprint. This thumbprint is used in e.g COS Security to match
     * a dealer. (Previously a special defined String was used).
     * Thumbprint is created from the x509certificate, sha'd and then shifted.
     *
     * @param x509Certificate     x509Certificate
     * @param thumbprintAlgorithm Algorithm to use. Default is sha-1 if the parameter is empty.
     * @return generated thumbprint
     * @throws CertificateException _
     */
    public static String getCertificateThumbprint(final X509Certificate x509Certificate, final String thumbprintAlgorithm)
            throws Exception {
        try {
            return generateThumbprint(x509Certificate.getEncoded(),
                    (thumbprintAlgorithm != null && !thumbprintAlgorithm.equals("") ? thumbprintAlgorithm : "sha"));
        } catch (Exception e) {
            LOG.severe(E_UNABLE_TO_RETRIEVE_THUMBPRINT_FROM_CERTIFICATE);
        }
        throw new Exception(E_UNABLE_TO_GENERATE_FINGERPRINT);
    }

    /**
     * Get the dealerId
     *
     * @param o x509Certificate or string as subject
     * @return Integer representing the dealerId (-1 if not found)
     * @throws CertificateException _
     */
    public static String getDealerName(final Object o) throws CertificateException {
        String dealerName = "";
        if (o != null) {
            if (o instanceof X509Certificate) {
                dealerName = findDealerNameWithinCommonName(getCommonName_x509((X509Certificate) o));
            } else if (o instanceof String) {
                dealerName = findDealerNameWithinCommonName(getCommonName(String.valueOf(o)));
            }
        }
        return dealerName;
    }

    /**
     * Get the dealerId
     *
     * @param o x509Certificate or string as subject
     * @return Integer representing the dealerId (-1 if not found)
     * @throws CertificateException _
     */
    public static Integer getDealerId(final Object o) throws CertificateException {
        Integer dealerId = NOT_FOUND;
        if (o != null) {
            if (o instanceof X509Certificate) {
                dealerId = findDealerIdWithinCommonName(getCommonName_x509((X509Certificate) o));
            } else if (o instanceof String) {
                dealerId = findDealerIdWithinCommonName(getCommonName(String.valueOf(o)));
            }
        }
        return dealerId;
    }

    /**
     * Use this if you are possessing the CN-field value only
     *
     * @param cnField commonName
     * @return dealerId (-1 if not found)
     */
    public static Integer getDealerIdFromCNFieldValue(final String cnField) {
        Integer dealerId = NOT_FOUND;
        if (cnField != null && !cnField.equals("")) {
            dealerId = findDealerIdWithinCommonName(cnField);
        }
        return dealerId;
    }

    public static String getCommonName(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.COMMON_NAME)));
    }

    public static String getOrganization(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.ORGANIZATION)));
    }

    public static List<String> getOrganizationUnit(final String field) throws CertificateException {
        return getCertificateAttribute(field, CertificateFields.ORGANIZATION_UNIT);
    }

    public static String getStreet(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.STREET)));
    }

    public static String getState(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.STATE_OF_RESIDENCE)));
    }

    public static String getCountry(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.COUNTRY)));
    }

    public static String getEmailAddress(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.E_MAIL)));
    }

    public static String getLocality(final String field) throws CertificateException {
        return String.valueOf(getFirstElement(getCertificateAttribute(field, CertificateFields.LOCALITY)));
    }

    public static List<String> getOrganizationUnit_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getOrganizationUnit(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getOrganization_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getOrganization(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getStreet_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getStreet(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getState_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getState(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getCountry_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getCountry(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getLocality_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getLocality(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getEmailAddress_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getEmailAddress(getSubjectFromCertificate(x509Certificate, false));
    }

    public static String getCommonName_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getCommonName(getSubjectFromCertificate(x509Certificate, false));
    }

    public static List<String> getIssuerOrganizationUnit_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getOrganizationUnit(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerOrganization_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getOrganization(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerStreet_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getStreet(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerState_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getState(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerCountry_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getCountry(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerLocality_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getLocality(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerEmailAddress_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getEmailAddress(getSubjectFromCertificate(x509Certificate, true));
    }

    public static String getIssuerCommonName_x509(final X509Certificate x509Certificate) throws CertificateException {
        return getCommonName(getSubjectFromCertificate(x509Certificate, true));
    }

    /**
     * Public method of getCertificateAttribute.
     *
     * @param subject   Certificate attribute "Subject" (4.1.2.6)
     * @param fieldName See com.vegaasen.sec.certificate.common.CertificateFields
     * @return List of String was found by the fieldName
     */
    public static List<String> getCertificateField(final String subject, final String fieldName) {
        if (subject != null && !subject.equals("")) {
            try {
                return getCertificateAttribute(subject, fieldName);
            } catch (CertificateException e) {
                LOG.warning("Unable to fetch the field. Error was: \n" + e);
            }
        }
        return Collections.emptyList();
    }

    public static X509Certificate getCertificateFromByteArray(final byte[] bytes, String algorithm) {
        if (bytes != null) {
            algorithm = (!algorithm.equals("") ? algorithm : ALG_X_509);
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(algorithm);
                X509Certificate generatedCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));
                if (generatedCertificate != null) {
                    return generatedCertificate;
                }
            } catch (CertificateException e) {
                LOG.warning("Unable to detect certificate algorithm.\n" + e);
            }
        }
        return null;
    }

    /**
     * Read a certificate from a file.
     * todo: does not support pkcs7 and onwards..
     *
     * @param location  Location of the certificate (c:/.../../..?)
     * @param algorithm algorithm algorithm to use. Default is ALG_X_509
     * @return Certificate
     */
    public static Certificate getCertificateFromFile(final String location, String algorithm) {
        if (location != null && !location.equals("")) {
            algorithm = (!algorithm.equals("") ? algorithm : ALG_X_509);
            try {
                FileInputStream fis = new FileInputStream(location);
                return convertToCertificate(fis, algorithm);
            } catch (FileNotFoundException e) {
                LOG.warning(String.format("Unable to find file on location %s", location));
            }
        }
        throw new NullPointerException(String.format("Provided certificate-location was empty. Location: {%s}", location));
    }

    /**
     * Generate a certificate from a give input. The input might be base64-encoded (---BEGIN--etc..), or something else.
     *
     * @param certificate certificate as string
     * @param algorithm   algorithm to use. Default is ALG_X_509
     * @return Certificate
     * @throws CertificateException _
     */
    public static Certificate getCertificateFromString(final String certificate, String algorithm) throws CertificateException {
        if (certificate != null && !certificate.equals("")) {
            algorithm = (!algorithm.equals("") ? algorithm : ALG_X_509);
            BufferedInputStream is = new BufferedInputStream(
                    new ByteArrayInputStream(
                            convertPemToValidSunFormat(certificate)
                    )
            );
            return convertToCertificate(is, algorithm);
        }
        throw new CertificateException(String.format("Provided certificate was empty."));
    }

    /**
     * @param request provided request
     * @return certificate from the request
     * @throws IllegalArgumentException _
     */
    public static X509Certificate getCertificateFromRequest(final HttpServletRequest request)
            throws IllegalArgumentException {
        if (request != null) {
            if (request.getAttribute(JAVA_SERVLET_REQUEST_X509_CERTIFICATE) != null) {
                X509Certificate x509certs[] =
                        (X509Certificate[]) request.getAttribute(JAVA_SERVLET_REQUEST_X509_CERTIFICATE);
                if (x509certs != null) {
                    return x509certs[0];
                    /*
                    as of right now, this is not supported.
                    for (X509Certificate cer : x509certs) {
                        // must test this - unsure of the output, as both root - inter - client will be present here.. how to separate these?
                    }*/
                }
                LOG.warning("No certificates found within request-object.");
                return null;
            }
        }
        throw new IllegalArgumentException(E_NO_REQUEST_OBJECT_PRESENT);
    }

    /**
     * Returns a certificate-object from the provided request (relies on headers.
     * if not found as one of the request-headers, an CertificateException will be thrown.
     *
     * @param request httpservletrequest
     * @return certificate from request
     * @throws CertificateException _
     */
    public static X509Certificate getCertificateFromRequestHeader(final HttpServletRequest request) throws CertificateException {
        if (null != request) {
            String certificateAsPem = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM);
            Certificate c = getCertificateFromString(certificateAsPem, "");
            if (c != null) {
                return (X509Certificate) c;
            }
            LOG.warning(String.format("Unable to read the following certificate from String:\n%s", certificateAsPem));
            throw new CertificateException("Returned certificate was null. Check log for more information.");
        }
        throw new IllegalArgumentException(E_NO_REQUEST_OBJECT_PRESENT);
    }

    /**
     * Convert a non-valid subject to a valid-subject. Delimiter is required.
     *
     * @param subject   the subject in question
     * @param delimiter your current delimiter. The valid delimiter is ",". Must be regexp. E.g: "\\/"
     * @return converted subject
     * @throws CertificateException _
     */
    public static String convertToLegalSubjectFormat(String subject, String delimiter) throws CertificateException {
        if (subject != null && !subject.equals("")) {
            if (delimiter == null || delimiter.equals("")) {
                delimiter = COMMA_DELIMITER;
            }
            if (subject.contains(delimiter)) {
                if (subject.contains(COMMA_DELIMITER)) {
                    subject = subject.replaceAll(COMMA_DELIMITER, "\\\\,");
                }
                subject = subject.replaceAll(delimiter, COMMA_DELIMITER);
                if (subject.indexOf(COMMA_DELIMITER) == 0) {
                    subject = subject.substring(1, subject.length());
                }
                try {
                    new LdapName(subject);
                } catch (InvalidNameException e) {
                    LOG.warning(
                            String.format("Unable to verify subject, even after conversion.\nSubject %s", subject));
                    throw new CertificateException("Unable to verify subject. Check your delimiter.");
                }
                System.gc();
            }
        }
        return subject;
    }

    /**
     * Simple function that verifies an inserted csr.
     * <p/>
     * Note: Not implemented yet.
     *
     * @param csrInput _
     * @return _
     */
    public static boolean isCSRInputValid(final String csrInput) {
        if (null != csrInput && !csrInput.equals("")) {
            if (csrInput.matches(REGEX_VALID_CSR)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Simple method that fetches a CA for supplied dnsName. If the outputTrustStoreFile is not specified,
     * it will use the trustStoreFile as its saving-location.
     *
     * @param dnsName              dns name entry. without slashes, protocol etc.
     * @param trustStorePassword   password for trust store
     * @param trustStoreFile       trust store-file
     * @param outputTrustStoreFile output-trust store
     * @return true | false
     * @throws Exception _
     */
    public static boolean getCAsForHostname(
            String dnsName,
            final String trustStorePassword,
            final File trustStoreFile,
            File outputTrustStoreFile
    ) throws Exception {
        if (dnsName != null && !dnsName.isEmpty() &&
                trustStorePassword != null && !trustStorePassword.isEmpty() &&
                trustStoreFile != null && trustStoreFile.exists()) {
            int port = DEFAULT_HTTPS_PORT;
            char[] passPhrase = trustStorePassword.toCharArray();
            if (dnsName.contains(PORT_IDENTIFIER)) {
                String[] c = dnsName.split(PORT_IDENTIFIER);
                if (c.length > 1) port = Integer.parseInt(c[1]);
                dnsName = c[0];
            }

            InputStream in = new FileInputStream(trustStoreFile);
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(in, passPhrase);
            in.close();
            try {
                SSLContext context = SSLContext.getInstance("TLS");
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(ks);
                X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
                SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
                context.init(null, new TrustManager[]{tm}, null);
                SSLSocketFactory factory = context.getSocketFactory();

                LOG.info("Opening connection to " + dnsName + ":" + port);
                SSLSocket socket = (SSLSocket) factory.createSocket(dnsName, port);
                socket.setSoTimeout(DEFAULT_TIMEOUT);
                try {
                    socket.startHandshake();
                    socket.close();
                    LOG.info("Already trusted.");
                } catch (SSLException e) {
                    LOG.info("Not trusted, will try to fetch CAs");
                }

                X509Certificate[] chain = tm.chain;
                if (chain == null) {
                    LOG.severe("Could not obtain server certificate chain");
                    return false;
                }

                MessageDigest sha1 = MessageDigest.getInstance("SHA1");
                MessageDigest md5 = MessageDigest.getInstance("MD5");
                for (X509Certificate cert : chain) {
                    sha1.update(cert.getEncoded());
                    md5.update(cert.getEncoded());
                }

                final int k = 0;
                X509Certificate cert = chain[k];
                String alias = dnsName + "-" + (1);
                ks.setCertificateEntry(alias, cert);

                if (outputTrustStoreFile == null) {
                    outputTrustStoreFile = trustStoreFile;
                }
                OutputStream out = new FileOutputStream(outputTrustStoreFile);
                ks.store(out, passPhrase);
                out.close();
                return true;
            } catch (NoSuchAlgorithmException e) {
                LOG.info("Unable to retrieve SSLContext.");
                return false;
            }
        }
        return false;
    }


    private static Certificate convertToCertificate(final InputStream is, String algorithm) {
        if (is != null && algorithm != null && !algorithm.equals("")) {
            try {
                return CertificateFactory.getInstance(algorithm).generateCertificate(is);
            } catch (CertificateException e) {
                LOG.warning(String.format("Unable to use algorithm-converter %s", algorithm));
                throw new IllegalArgumentException("Algorithm is wrong. Please specify a valid algorithm.");
            }
        }
        throw new IllegalArgumentException("");
    }

    private static String getSubjectFromCertificate(final X509Certificate x509Certificate, final boolean issuer) throws CertificateException {
        if (isCertificatePresent(x509Certificate)) {
            if (issuer) {
                return x509Certificate.getIssuerX500Principal().getName();
            } else {
                return x509Certificate.getSubjectX500Principal().getName();
            }
        }
        throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
    }

    private static String generateThumbprint(final byte[] certificateBytes, final String algorithm) throws Exception {
        if (certificateBytes.length > 0 && !algorithm.equals("")) {
            try {
                MessageDigest digest = MessageDigest.getInstance(algorithm);
                digest.update(certificateBytes);
                byte[] digestedByte = digest.digest();
                String hexedResult = "";
                for (byte b : digestedByte) {
                    int bb = b & 0xff;
                    String hexed = Integer.toHexString(bb);
                    hexedResult += (hexed.length() == 1) ? "0" : hexed;
                }
                return hexedResult;
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
    }

    private static List<String> getCertificateAttribute(final String subject, final String certificateField)
            throws CertificateException {
        if (subject != null && !subject.equals("")) {
            try {
                final LdapName ldap = new LdapName(subject);
                if (ldap.getRdns() != null && ldap.getRdns().size() > 0) {
                    List<String> sv = new ArrayList<String>();
                    for (Rdn rdn : ldap.getRdns()) {
                        if (rdn != null && rdn.getType() != null) {
                            String currentType = rdn.getType();
                            if (certificateField.equals(currentType) && rdn.getValue() != null) {
                                sv.add(rdn.getValue().toString());
                            }
                        }
                    }
                    return sv;
                }
            } catch (InvalidNameException e) {
                LOG.warning(
                        "Unable to create new instance of the LdapName. Trying once more with reformatted subject.");
                try {
                    if (subject.contains("=")) {
                        return getCertificateAttribute(
                                convertToLegalSubjectFormat(subject.replaceAll(REGEX_INVALID_SUBJECT_CONTENT, REGEXP_REPLACEMENT_OF_INVALID_SUBJECT), "/"),
                                certificateField);
                    }
                } catch (CertificateException ex) {
                    throw new CertificateException(E_ILLEGAL_FORMAT_ON_SUBJECT_SUPPLIED);
                }
            }
        }
        throw new CertificateException(E_CERTIFICATE_NO_SUBJECT_SUPPLIED);
    }

    private static Integer findDealerIdWithinCommonName(final String commonName) {
        if (commonName != null && !commonName.equals("")) {
            String numerical = commonName.replaceAll(REGEX_NUMERICAL_ONLY, "");
            if (numerical.startsWith("0")) {
                numerical = numerical.substring(1, numerical.length());
            }
            if (numerical.equals("")) {
                return MISSING_NUMERICAL;
            }
            return Integer.parseInt(numerical);
        }
        return NOT_FOUND;
    }

    private static String findDealerNameWithinCommonName(final String commonName) {
        if (commonName != null && !commonName.isEmpty() && commonName.contains("-")) {
            String name = commonName.substring(commonName.indexOf("-"), commonName.length());
            if (!name.isEmpty()) {
                return name.substring(1, name.length()).trim();
            }
        }
        return EMPTY;
    }

    private static double round(double valueToRound, int numberOfDecimalPlaces) {
        double multipicationFactor = Math.pow(10, numberOfDecimalPlaces);
        double interestedInZeroDPs = valueToRound * multipicationFactor;
        return Math.round(interestedInZeroDPs) / multipicationFactor;
    }

    /**
     * Fixes a failing PEM. replacing \s with \n. Important, otherwise the Sun implementation will actually fail..
     *
     * @param pem PEM to be enhanced
     * @return "healthy PEM"
     */
    public static byte[] convertPemToValidSunFormat(String pem) {
        if (pem != null && !pem.isEmpty()) {
            pem = pem.replace(BEGIN_CERTIFICATE, "");
            pem = pem.replace(END_CERTIFICATE, "");
            pem = pem.replaceAll("\\s", "\n");
            pem = BEGIN_CERTIFICATE + pem + END_CERTIFICATE;
            return pem.getBytes();
        }
        return new byte[]{};
    }

    /**
     * Append separators to the String. Typically serial numbers might require this
     * (?<=..)(..) --> lookBehind to find two chars
     *
     * @return separated string in lower case
     */
    static String appendSeparators(final String candidate) {
        if (candidate == null || candidate.isEmpty()) {
            return EMPTY;
        }
        final String formatted = candidate.replaceAll("(?<=..)(..)", ":$1");
        return (formatted != null && !formatted.isEmpty()) ? formatted.toLowerCase() : EMPTY;
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}
