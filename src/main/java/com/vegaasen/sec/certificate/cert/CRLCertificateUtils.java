package com.vegaasen.sec.certificate.cert;

import com.vegaasen.sec.certificate.abs.UtilsAbstract;
import com.vegaasen.sec.certificate.common.ConnectionVariant;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.vegaasen.sec.certificate.common.CertificateProperties.PROTOL_IDENT;
import static com.vegaasen.sec.certificate.common.CertificateProperties.RXP_URL_VALIDATION;
import static com.vegaasen.sec.certificate.common.CertificateReferences.CRL_DISTRIBUTION_POINTS;
import static com.vegaasen.sec.certificate.common.CommonErrors.E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED;

/**
 * @author nissen
 */
public final class CRLCertificateUtils extends UtilsAbstract {

    private static final Logger LOGGER = Logger.getLogger(CRLCertificateUtils.class.getName());
    private static final int ARR_LENGTH = 10;

    public static void getRevokedCertificates() {
        throw new IllegalStateException("Not implemented yet.");
    }

    /**
     * Initial method, revisit. Its not that stable as of 07.09.2012.
     *
     * @param certificate _
     * @return List of URLs recorded from the x509-encoded certificate
     * @throws CertificateException _
     */
    public static List<String> getDistributionPoints(final X509Certificate certificate)
            throws CertificateException {
        if (isCertificatePresent(certificate)) {
            byte[] crlInput = certificate.getExtensionValue(CRL_DISTRIBUTION_POINTS);
            if (crlInput != null && crlInput.length > 0) {
                String decodedCrlInput = new String(crlInput, Charset.forName("utf-8"));
                int[] locations = new int[ARR_LENGTH];
                int location = 0, counter = 0;
                for (; ; ) {
                    if (location > 0) location++;
                    location = decodedCrlInput.indexOf("http", location + 1);
                    if (location > 0) {
                        locations[counter] = location;
                        counter++;
                    } else {
                        break;
                    }
                }
                if (locations.length > 0) {
                    String[] crlLocations = new String[ARR_LENGTH];
                    counter = 0;
                    for (int loc : locations) {
                        if ((counter > 0 && loc > 0) || (counter == 0)) {
                            crlLocations[counter] = decodedCrlInput.substring(loc);
                            counter++;
                        } else {
                            break;
                        }
                    }
                    return Arrays.asList(crlLocations);
                }
            }
            throw new CertificateException(
                    "There was a problem reading the CRL-list related to the certificate. No CRL found"
            );
        }
        throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
    }

    public static X509Certificate getCrlListFromURL(final String urlLocation)
            throws IllegalArgumentException, IOException {
        if (urlLocation != null && !urlLocation.equals("")) {
            final Pattern pattern = Pattern.compile(RXP_URL_VALIDATION);
            Matcher matcher = pattern.matcher(urlLocation);
            if (matcher.matches()) {
                URL url = new URL(urlLocation);
                InputStream is = null;
                if (urlLocation.contains(ConnectionVariant.HTTP.toString() + PROTOL_IDENT)) {
                    try {
                        is = getInputStreamFromURL(url);
                    } catch (IOException e) {
                        LOGGER.severe("Unable to get InputStream from http");
                    }
                } else if (urlLocation.contains(ConnectionVariant.HTTPS.toString() + PROTOL_IDENT)) {
                    try {
                        is = getInputStreamFromURL(url);
                    } catch (IOException e) {
                        LOGGER.severe("Unable to get InputStream from https");
                    }
                }
                if (is != null) {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    int r;
                    byte[] crlData = new byte[65553];
                    while ((r = is.read(crlData, 0, crlData.length)) != -1) {
                        baos.write(crlData, 0, r);
                    }
                    baos.close();
                    baos.flush();
                    if (crlData.length > 0) {
                        @SuppressWarnings("unused") byte[] crlIsAsByte = getStringFromInputStream(is).getBytes();
                    }
                }
                throw new IOException("Unable to enhance the input");
            } else {
                throw new MalformedURLException(
                        String.format("urlLocation provided was malformed\nUrlLocation:%s", urlLocation)
                );
            }
        }
        throw new IllegalArgumentException("Argument was null or empty.");
    }

}
