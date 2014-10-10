package com.vegaasen.sec.certificate.cert;

import com.vegaasen.sec.certificate.common.CertificateProperties;
import com.vegaasen.sec.certificate.common.CertificateReferences;
import com.vegaasen.sec.certificate.common.CertificateTestCommon;
import com.vegaasen.sec.certificate.http.SslHeaders;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.File;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({SslHeaders.class})
@PowerMockIgnore("javax.security.*")
public class CertificateUtilsTest {

    private static final String
            EXPECTED_THUMBPRINT_RESULT_SHA1 = "3afbe6e4ba86bd5363c76cb0545a17f663ef3155",
            EXPECTED_THUMBPRINT_RESULT_MD5 = "12dd4f9adee15175c1aedc87af17b7ac";
    private X509Certificate certificate;

    /**
     * Mock request.
     */
    private HttpServletRequest request;

    /**
     * Mock session.
     */
    private HttpSession session;

    /**
     * Session's attribute map.
     */
    private Map attributes;

    /**
     * Request's parameter map.
     */
    private Map parameters;

    private SslHeaders sslHeaders;

    @Before
    public void setUp() {
        certificate = CertificateUtils.getCertificateFromByteArray(CertificateTestCommon.VALID_CERTIFICATE_BYTES, "");

        attributes = new HashMap();
        parameters = new HashMap();

        request = mock(HttpServletRequest.class);
        session = mock(HttpSession.class);

        when(request.getSession()).thenReturn(session);
        when(request.getParameterMap()).thenReturn(parameters);
    }

    /**
     * Will give an exception for NoSuchAlgorithmException, no worries, its supposed to happen.
     *
     * @throws Exception _
     */
    @Test(expected = Exception.class)
    public void testGenerateThumbprint_shouldFailOnWrongDigest() throws Exception {
        CertificateUtils.getCertificateThumbprint(certificate, "shaa");
    }

    @Test(expected = Exception.class)
    public void testGenerateThumbprint_shouldFailOnNullCertificate() throws Exception {
        certificate = null;
        CertificateUtils.getCertificateThumbprint(certificate, "shaa");
    }

    @Test
    public void testGenerateThumbprint_shouldGenerateValidThumbprint_emptyAlgorithm() throws Exception {
        String thumbprint = CertificateUtils.getCertificateThumbprint(certificate, "");
        assertTrue(thumbprint != null);
        assertTrue(!thumbprint.equals(""));
        assertEquals(thumbprint, EXPECTED_THUMBPRINT_RESULT_SHA1);
    }

    @Test
    public void testGenerateThumbprint_shouldGenerateValidThumbprint_sha1Algorithm() throws Exception {
        String thumbprint = CertificateUtils.getCertificateThumbprint(certificate, "sha-1");
        assertTrue(thumbprint != null);
        assertTrue(!thumbprint.equals(""));
        assertEquals(thumbprint, EXPECTED_THUMBPRINT_RESULT_SHA1);
    }

    @Test
    public void testGenerateThumbprint_shouldGenerateThumbprint_md5Algorithm() throws Exception {
        String thumbprint = CertificateUtils.getCertificateThumbprint(certificate, "md5");
        assertTrue(thumbprint != null);
        assertTrue(!thumbprint.equals(""));
        assertEquals(thumbprint, EXPECTED_THUMBPRINT_RESULT_MD5);
    }

    @Test
    public void testGenerateCosSecurityString_oldType() throws CertificateException {
        final String expectedCosString = "CN=Telenor Norge AS Dealer CA, OU=Symantec Trust Network, OU=Class 2 Managed PKI Individual Subscriber CA, O=Telenor Norge AS, C=NO, dealerId=375";

        String cosSecurityString = CertificateUtils.getCosSecurityFormattedString(certificate, false);

        assertNotNull(cosSecurityString);
        assertTrue(!cosSecurityString.equals(""));
        assertEquals(expectedCosString, cosSecurityString);
    }

    @Test
    public void testGenerateCosSecurity_newType_fingerprintBased() throws Exception {
        final String expectedResult = "3afbe6e4ba86bd5363c76cb0545a17f663ef3155, dealerId=375";

        String result = CertificateUtils.getCosSecurityFormattedStringBasedOnThumbprint(certificate);

        assertNotNull(result);
        assertTrue(!result.equals(""));
        assertEquals(expectedResult, result);
    }

    @Test
    public void testGetCommonName() throws CertificateException {
        final String expectedCommonName = "375 - Test Online Forhandler";
        X509Certificate c = (X509Certificate) CertificateUtils.getCertificateFromString(
                CertificateTestCommon.CERTIFICATE_CLAVIS_375,
                CertificateProperties.ALG_X_509);
        assertNotNull(c);
        assertTrue(c.getVersion() == 3);

        String commonName = CertificateUtils.getCommonName_x509(c);
        assertNotNull(commonName);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);
    }

    @Test
    public void testGetDealerId_375() throws CertificateException {
        final Integer expectedDealerId = 375;
        X509Certificate c = getValidCertificate();
        assertNotNull(c);
        Integer dealerId = CertificateUtils.getDealerId(c);
        assertNotNull(dealerId);
        assertTrue(dealerId > 0);
        assertEquals(expectedDealerId, dealerId);
    }

    @Test
    public void testGetOrganizationUnit_x509_shouldFindMultiAllowed() throws CertificateException {
        List<String> ous = CertificateUtils.getOrganizationUnit_x509(certificate);
        assertNotNull(ous);
        assertTrue(!ous.isEmpty());
        assertEquals(2, ous.size());
        assertTrue(ous.contains("MULTI-ALLOWED"));
    }

    @Test
    public void getCertificate_importWorksFine() throws CertificateException {
        X509Certificate c = (X509Certificate) CertificateUtils.getCertificateFromString(
                CertificateTestCommon.CERTIFICATE_CLAVIS_375,
                CertificateProperties.ALG_X_509);
        assertNotNull(c);
    }

    @Test
    public void testShouldFindCorrectCountry() throws CertificateException {
        final String expectedCountry = "NO";
        String country = CertificateUtils.getCountry_x509(certificate);
        assertNotNull(country);
        assertTrue(!country.equals(""));
        assertEquals(country, expectedCountry);
    }

    @Test(expected = CertificateException.class)
    public void testShouldFailMissingCertificate() throws CertificateException {
        CertificateUtils.getCountry_x509(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void getCertificate_shouldFailFromInput() throws CertificateException, IllegalArgumentException {
        CertificateUtils.getCertificateFromString(
                CertificateTestCommon.CERTIFICATE_CLAVIS_375_CORRUPTED_INPUT, CertificateProperties.ALG_X_509);
    }

    @Test
    public void testShouldFindPemFormattedCertificate_AsHeaderFromRequest() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);
        X509Certificate pemFormatted = CertificateUtils.getCertificateFromRequestHeader(request);
        assertNotNull(pemFormatted);
        assertTrue(pemFormatted.getType().equals("X.509"));
        assertTrue(pemFormatted.getSigAlgName().equals("SHA1withRSA"));

        final String expectedSubject = "CN=375 - Test Online Forhandler, OU=MULTI-ALLOWED, O=Telenor Norge AS, EMAILADDRESS=vegard.aasen@telenor.com, C=NO, L=\"Att: Kim André Skjerpen, L6C,  Snarøyv 3 1331 Fornebu\", OID.1.2.840.113549.1.9.2=TNA-01-3908, OU=0";
        String subject = pemFormatted.getSubjectDN().getName();
        assertNotNull(subject);
        assertTrue(!subject.equals(""));
        assertEquals(expectedSubject, subject);

        final String expectedCommonName = "375 - Test Online Forhandler";
        String commonName = CertificateUtils.getCommonName_x509(pemFormatted);
        assertNotNull(commonName);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);

        String commonNameFromSubject = CertificateUtils.getCommonName(subject);
        assertNotNull(commonNameFromSubject);
        assertTrue(!commonNameFromSubject.equals(""));
        assertEquals(expectedCommonName, commonNameFromSubject);
    }

    @Test
    public void testShouldFindPemFormattedCertificate_AsAttributeFromRequest() throws CertificateException {
        X509Certificate[] certArray = new X509Certificate[2];
        certArray[0] = certificate;
        when(request.getAttribute("java.servlet.request.X509Certificate")).thenReturn(certArray);
        X509Certificate pemFormatted = CertificateUtils.getCertificateFromRequest(request);
        assertNotNull(pemFormatted);
        assertTrue(pemFormatted.getType().equals("X.509"));
        assertTrue(pemFormatted.getSigAlgName().equals("SHA1withRSA"));

        final String expectedSubject = "CN=375 - Test Online Forhandler, OU=MULTI-ALLOWED, O=Telenor Norge AS, EMAILADDRESS=vegard.aasen@telenor.com, C=NO, L=\"Att: Kim André Skjerpen, L6C,  Snarøyv 3 1331 Fornebu\", OID.1.2.840.113549.1.9.2=TNA-01-3908, OU=0";
        String subject = pemFormatted.getSubjectDN().getName();
        assertNotNull(subject);
        assertTrue(!subject.equals(""));
        assertEquals(expectedSubject, subject);

        final String expectedCommonName = "375 - Test Online Forhandler";
        String commonName = CertificateUtils.getCommonName_x509(pemFormatted);
        assertNotNull(commonName);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);

        String commonNameFromSubject = CertificateUtils.getCommonName(subject);
        assertNotNull(commonNameFromSubject);
        assertTrue(!commonNameFromSubject.equals(""));
        assertEquals(expectedCommonName, commonNameFromSubject);
    }

    @Test
    public void testShouldGenerateDate_verifyTrueDate() throws CertificateException {
        final long timeSpanToMeasureFrom = 1350927644234L;
        final Date theDateFromMeasureLong = new Date(timeSpanToMeasureFrom);
        Double expiration =
                CertificateUtils.getSpanUntilExpiration(certificate, theDateFromMeasureLong, Unit.WEEKS),
                expectedWeeks = 92.0,
                expectedDays = 649.0,
                expectedMinutes = 934939.0,
                expectedMonths = 23.0,
                delta = 1.0;
        assertNotNull(expiration);
        assertTrue(0L != expiration);
        assertEquals(expiration, expectedWeeks, expectedWeeks + delta);

        expiration = CertificateUtils.getSpanUntilExpiration(certificate, theDateFromMeasureLong, Unit.DAYS);
        assertNotNull(expiration);
        assertTrue(0L != expiration);
        assertEquals(expectedDays, expiration, expectedDays + delta);

        assertEquals((expectedWeeks * 7), expiration, expectedDays + delta);

        expiration = CertificateUtils.getSpanUntilExpiration(certificate, theDateFromMeasureLong, Unit.MINUTES);
        assertNotNull(expiration);
        assertTrue(0L != expiration);
        assertEquals(expectedMinutes, expiration, expectedMinutes + delta);

        expiration = CertificateUtils.getSpanUntilExpiration(certificate, theDateFromMeasureLong, Unit.MONTHS);
        assertNotNull(expiration);
        assertTrue(0L != expiration);
        assertEquals(expectedMonths, expiration, expectedMonths + delta);
    }

    @Test
    @Ignore("Certificate has expired.")
    public void testValidExpirationDate() throws CertificateException {
        long fromNowOn = 100L; //hmmm..this might suddenly fail in the near (+2y)
        boolean result = CertificateUtils.validExpirationDate(certificate, fromNowOn);
        assertTrue(result);
    }

    @Test
    public void testGetExtensionValue_SubjectKeyIdentifier() throws CertificateException {
        byte[] result = CertificateUtils.getExtensionValue(certificate, CertificateReferences.SUBJECT_KEY_IDENTIFIER);
        assertNotNull(result);
        assertTrue(result.length != 0);
        String resultAsString = new String(result);
        assertNotNull(resultAsString);
    }

    @Test
    @Ignore(value = "There are some errors with the SSLContext. Please ignore untill fixed.")
    public void testAddCertificateToTrustStore_shouldAddByDnsName() throws Exception {
        final String dnsName = "www.telenor.no";
        final String trustStorePassword = "changeit";
        final String location = System.getProperty("java.home") + File.separator + "lib" + File.separator + "security" +
                File.separator + "cacerts";
        final File trustStoreFileLocation = new File(location);
        final String tmpLocation = System.getProperty("java.io.tmpdir") + File.separator + "testcacerts";
        final File outputTrustStoreSaveLocation = new File(tmpLocation);
        boolean result = CertificateUtils.getCAsForHostname(dnsName, trustStorePassword, trustStoreFileLocation, outputTrustStoreSaveLocation);
        assertTrue(result);
        assertTrue(outputTrustStoreSaveLocation.exists());
    }

    @Test
    public void shouldConvertSerialNumberToSpecificFancyFormat() {
        final String result = CertificateUtils.appendSeparators("2a2741fc3909cad47e6613b4b18ed395");
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void shouldConvertSerialNumberToSpecificFancyFormatWithUpperCase() {
        final String result = CertificateUtils.appendSeparators("77B1EC57CCAD515FACD163185FBD92F1");
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("77:b1:ec:57:cc:ad:51:5f:ac:d1:63:18:5f:bd:92:f1", result);
    }

    @Test
    public void shouldGetCommonNameFromHeader() throws CertificateException {
        final String result = CertificateUtils.getCommonName("CN=7777 - Kundeservice Fornebu,signingTime=1384255362730,unstructuredAddress=45088650,ST=NO,OU=MULTI-ALLOWED,O=Telenor Norge AS,C=NO,L=Snarøyv 30\\, L6c 1331 SNARØYA,unstructuredName=vegard-test,OU=0/ST=Huey - Dewey - Louie");
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("7777 - Kundeservice Fornebu", result);
    }

    @Test
    public void shouldGetCommonNameFromHeader_spaceshit() throws CertificateException {
        final String result = CertificateUtils.getCommonName("CN=7777 - Kundeservice Fornebu, signingTime=1384255362730, unstructuredAddress=45088650, ST=NO, OU=MULTI-ALLOWED, O=Telenor Norge AS, C=NO, L=Snarøyv 30\\, L6c 1331 SNARØYA, unstructuredName=vegard-test, OU=0/ST=Huey - Dewey - Louie");
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("7777 - Kundeservice Fornebu", result);
    }

    private static X509Certificate getValidCertificate() throws CertificateException {
        return (X509Certificate) CertificateUtils.getCertificateFromString(
                CertificateTestCommon.CERTIFICATE_CLAVIS_375,
                CertificateProperties.ALG_X_509);
    }

}
