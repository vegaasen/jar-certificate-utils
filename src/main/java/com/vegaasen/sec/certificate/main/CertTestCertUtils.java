package com.vegaasen.sec.certificate.main;

import com.vegaasen.sec.certificate.cert.CRLCertificateUtils;
import com.vegaasen.sec.certificate.cert.CertificateUtils;

import java.security.cert.X509Certificate;

/**
 * Simple runnable
 */
public class CertTestCertUtils {

    public static void main(String... args) {
        try {
            X509Certificate c = (X509Certificate) CertificateUtils.getCertificateFromFile("C:\\Temp\\cer\\375_BASE64-x509.cer", "");
            System.out.println(c.getSerialNumber());
            System.out.println(CRLCertificateUtils.getDistributionPoints(c));
            //System.out.println(CRLCertificateUtils.getCrlListFromURL("http://pki-crl.symauth.com/ca_39765b7891fd9994ace4fb769484d536/LatestCRL.crl"));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
