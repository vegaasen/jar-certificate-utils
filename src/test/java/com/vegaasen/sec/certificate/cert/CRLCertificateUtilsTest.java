package com.vegaasen.sec.certificate.cert;

import org.junit.Ignore;
import org.junit.Test;

import java.io.IOException;
import java.security.cert.X509Certificate;

import static org.junit.Assert.assertNotNull;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 * @since 3:59 PM
 */
public final class CRLCertificateUtilsTest {

    @Test(expected = IllegalStateException.class)
    public void getRevokedCertificates_notImplemented_fail() {
        CRLCertificateUtils.getRevokedCertificates();
    }

    @Test
    @Ignore("Not operational yet.")
    public void getCrlListFromURL_getFromTelenor_no_ok() throws IOException {
        final X509Certificate certificate = CRLCertificateUtils.getCrlListFromURL("https://www.telenorforhandler.no");
        assertNotNull(certificate);
    }

}
