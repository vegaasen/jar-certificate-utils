package com.vegaasen.sec.certificate.abs;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Scanner;
import java.util.logging.Logger;

import static com.vegaasen.sec.certificate.common.CommonErrors.E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED;

public abstract class UtilsAbstract {

    private static final Logger LOGGER = Logger.getLogger(UtilsAbstract.class.getName());
    private static final String UTF_8 = "UTF-8";
    private static final String DELIM = "\\A";
    private static final String WRITE_LOC = System.getProperty("java.io.tmpdir") + File.separatorChar + "downloaded.crl";

    protected static boolean isCertificatePresent(final X509Certificate x509Certificate)
            throws CertificateException {
        if (x509Certificate != null) {
            return true;
        }
        throw new CertificateException(E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED);
    }

    protected static InputStream getInputStreamFromURL(final URL url)
            throws IllegalArgumentException, IOException {
        if (url != null && !url.toString().equals("")) {
            InputStream is = url.openStream();
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(is));
            File f = new File(WRITE_LOC);
            FileWriter fileWriter = new FileWriter(f.getAbsoluteFile());
            BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
            String line;
            while ((line = bufferedReader.readLine()) != null) {
                bufferedWriter.write(line);
            }
            bufferedReader.close();
            bufferedWriter.close();
            is.close();
            return is;
        }
        throw new IllegalArgumentException("Argument was null or empty.");
    }

    protected static String getStringFromInputStream(final InputStream inputStream)
            throws IllegalArgumentException {
        if (inputStream != null) {
            try {
                Scanner scanner = new Scanner(inputStream, UTF_8).useDelimiter(DELIM);
                if (scanner.hasNext()) {
                    return scanner.next();
                }
            } catch (NoSuchElementException e) {
                LOGGER.severe("Unable to scan supplied inputStream");
            }
            return "";
        }
        throw new IllegalArgumentException("Inputstream was null or undefined");
    }

    protected static Object getFirstElement(final List<?> elements) {
        if (elements != null) {
            if (elements.size() != 0) {
                return elements.get(0);
            }
        }
        return null;
    }

}
