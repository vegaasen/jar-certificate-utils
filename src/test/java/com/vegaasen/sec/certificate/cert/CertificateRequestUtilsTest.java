package com.vegaasen.sec.certificate.cert;

import com.vegaasen.sec.certificate.common.CertificateTestCommon;
import com.vegaasen.sec.certificate.http.SslHeaders;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({SslHeaders.class})
@PowerMockIgnore("javax.security.*")
public class CertificateRequestUtilsTest {

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
        attributes = new HashMap();
        parameters = new HashMap();

        request = mock(HttpServletRequest.class);
        session = mock(HttpSession.class);

        when(request.getSession()).thenReturn(session);
        when(request.getParameterMap()).thenReturn(parameters);
    }

    @Test
    public void testShouldGetCertificateFromRequest_isValid() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375_VALID);
        X509Certificate pemFormatted = CertificateRequestUtils.getCertificate(request);
        assertNotNull(pemFormatted);
        assertTrue(pemFormatted.getType().equals("X.509"));
        assertTrue(pemFormatted.getSigAlgName().equals("SHA1withRSA"));
    }

    @Test
    public void testShouldGetCertificateFromRequest() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);
        X509Certificate pemFormatted = CertificateRequestUtils.getCertificate(request);
        assertNotNull(pemFormatted);
        assertTrue(pemFormatted.getType().equals("X.509"));
        assertTrue(pemFormatted.getSigAlgName().equals("SHA1withRSA"));

        final String expectedSubject = "CN=375 - Test Online Forhandler, OU=MULTI-ALLOWED, O=Telenor Norge AS, EMAILADDRESS=vegard.aasen@telenor.com, C=NO, L=\"Att: Kim André Skjerpen, L6C,  Snarøyv 3 1331 Fornebu\", OID.1.2.840.113549.1.9.2=TNA-01-3908, OU=0";
        String subject = pemFormatted.getSubjectDN().getName();
        assertNotNull(subject);
        assertTrue(!subject.equals(""));
        assertEquals(expectedSubject, subject);
    }

    @Test
    public void testShouldGetCertificate_failWithIllegalArgExc() throws CertificateException {
        request = null;
        X509Certificate certificate = CertificateRequestUtils.getCertificate(request);
        assertTrue(certificate == null);
        assertNull(certificate);
    }

    @Test
    public void testShouldGetCertificate_failWithCertificateExc_noHeaderContent() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString())).thenReturn("");
        X509Certificate certificate = CertificateRequestUtils.getCertificate(request);
        assertTrue(certificate == null);
        assertNull(certificate);
    }

    @Test
    public void testShouldGetCertificate_failNoHeader() throws CertificateException {
        X509Certificate certificate = CertificateRequestUtils.getCertificate(request);
        assertTrue(certificate == null);
        assertNull(certificate);
    }

    @Test
    public void testGetDealerIdFromRequest_375() {
        final int expectedDealerId = 375;
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString())).thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_375);
        int dealerId = CertificateRequestUtils.getDealerId(request);
        assertNotNull(dealerId);
        assertTrue(dealerId > -1);
        assertEquals(expectedDealerId, dealerId);
    }

    @Test
    public void testGetDealerIdFromRequest_0375() {
        final int expectedDealerId = 375;
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_0375);
        int dealerId = CertificateRequestUtils.getDealerId(request);
        assertNotNull(dealerId);
        assertTrue(dealerId > -1);
        assertEquals(expectedDealerId, dealerId);
    }

    @Test
    public void testGetDealerNameFromRequest_375() {
        final String expectedDealerName = "Test Online Forhandler";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_375);
        String dealerName = CertificateRequestUtils.getDealerName(request);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerNameFromRequest_7777() {
        final String expectedDealerName = "Kundeservice Fornebu";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_7777);
        String dealerName = CertificateRequestUtils.getDealerName(request);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerNameFromRequest_OTL_SUP() {
        final String expectedDealerName = "OTL Testforhandler";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_OTL_SUP);
        String dealerName = CertificateRequestUtils.getDealerName(request);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerNameFromRequest_OTL_WEB() {
        final String expectedDealerName = "Hello Norway A/S";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_OTL_WEB);
        String dealerName = CertificateRequestUtils.getDealerName(request);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testShouldGetThumbprintFromRequest() throws CertificateException {
        final String expectedThumbprint = "3afbe6e4ba86bd5363c76cb0545a17f663ef3155";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);
        String thumbprintResult = CertificateRequestUtils.getCertificateThumbprint(request);
        assertNotNull(thumbprintResult);
        assertTrue(!thumbprintResult.isEmpty());
        assertEquals(expectedThumbprint, thumbprintResult);
    }

    @Test
    public void testShouldGetThumbprintFromRequest_valid() throws CertificateException {
        final String expectedThumbprint = "c842770b3df3668f5309b535c93490a03b770";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375_VALID);
        String thumbprintResult = CertificateRequestUtils.getCertificateThumbprint(request);
        assertNotNull(thumbprintResult);
        assertTrue(!thumbprintResult.isEmpty());
        assertEquals(expectedThumbprint, thumbprintResult);
    }

    @Test
    public void testShouldGetThumbprint_md5() throws CertificateException {
        final String expectedThumbprint = "12dd4f9adee15175c1aedc87af17b7ac";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);
        X509Certificate certificate = CertificateRequestUtils.getCertificate(request);
        assertNotNull(certificate);
        final String thumb = CertificateRequestUtils.getCertificateThumbprint(certificate, "MD5");
        assertNotNull(thumb);
        assertEquals(expectedThumbprint, thumb);
    }

    @Test
    public void testShouldGetThumbprintFromRequest_usingCertificate() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);
        X509Certificate pemFormatted = CertificateRequestUtils.getCertificate(request);
        assertNotNull(pemFormatted);
        assertTrue(pemFormatted.getType().equals("X.509"));
        assertTrue(pemFormatted.getSigAlgName().equals("SHA1withRSA"));

        final String expectedThumbprint = "3afbe6e4ba86bd5363c76cb0545a17f663ef3155";
        final String thumbprintResult = CertificateRequestUtils.getCertificateThumbprint(pemFormatted, "");
        assertNotNull(thumbprintResult);
        assertTrue(!thumbprintResult.isEmpty());
        assertEquals(expectedThumbprint, thumbprintResult);
    }

    @Test
    public void testShouldGetCommonNameFromRequest() {
        final String expectedResult = "375 - Test Online Forhandler";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_375);
        final String result = CertificateRequestUtils.getCommonName(request);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(expectedResult, result);
    }

    @Test
    public void testShouldGetSubjectFromRequest_375() {
        final String expectedResult = CertificateTestCommon.CLAVIS_SUBJECT_375;
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(CertificateTestCommon.CLAVIS_SUBJECT_375);
        final String result = CertificateRequestUtils.getSubject(request);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(expectedResult, result);
    }

    @Test
    public void testShouldGetExpireDateRequest_asDate() {
        final long expectedResult = 1418424313000L;
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_NOT_AFTER.toString()))
                .thenReturn("Dec 12 22:45:13 2014 GMT");
        final Date result = CertificateRequestUtils.getExpireDate(request);
        assertNotNull(result);
        assertEquals(expectedResult, result.getTime());
    }

    @Test
    public void testShouldGetExpireDateRequest_asDate_Windows() {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_NOT_AFTER.toString()))
                .thenReturn("Des 6 23:59:59 2014 GMT");
        final Date result = CertificateRequestUtils.getExpireDate(request);
        assertNotNull(result);
    }

    @Test
    public void testShouldGetSerialNumberRequest_asString() {
        final String expectedResult = "77B1EC57CCAD515FACD163185FBD92F1";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SERIAL_NUMBER.toString()))
                .thenReturn(expectedResult);
        final String result = CertificateRequestUtils.getSerialNumber(request);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(expectedResult, result);
    }

    @Test
    public void testShouldGetSerialNumberRequest_notFound_asString() {
        final String result = CertificateRequestUtils.getSerialNumber(request);
        assertNotNull(result);
        assertTrue(result.equals(""));
    }

    @Test
    public void testShouldGetSerialNumberRequest_formatted() {
        final String serialNumber = "77B1EC57CCAD515FACD163185FBD92F1";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SERIAL_NUMBER.toString()))
                .thenReturn(serialNumber);
        final String result = CertificateRequestUtils.getSerialNumber(request, true);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals("77:b1:ec:57:cc:ad:51:5f:ac:d1:63:18:5f:bd:92:f1", result);
    }

    @Test
    public void testShouldGetSerialNumberRequest_formattedLowerToLowe() {
        final String serialNumber = "77b1ec57ccad515facd163185fbd92f1";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SERIAL_NUMBER.toString()))
                .thenReturn(serialNumber);
        final String result = CertificateRequestUtils.getSerialNumber(request, true);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals("77:b1:ec:57:cc:ad:51:5f:ac:d1:63:18:5f:bd:92:f1", result);
    }

    @Test
    public void testValidExpirationDate() {
        final long allowedDate = 5;
        final long twoDaysFromNow = 172800000;
        final SimpleDateFormat apache_format = new SimpleDateFormat("MMM dd hh:mm:ss yyyy z");
        final String expectedResult = apache_format.format(new Date(System.currentTimeMillis() + twoDaysFromNow));
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_NOT_AFTER.toString()))
                .thenReturn(expectedResult);
        final boolean result = CertificateRequestUtils.isValidExpirationDate(request, allowedDate);
        assertNotNull(result);
        assertFalse(result);
    }

    @Test
    public void testGetDealerNameShouldBeValidSubject_byOTL() {
        String subject = "/CN=OTLWEB-Talkmore AS/OU=0/unstructuredName=TNA-01-3908-Vegaa/L=Dronningsgt 6 152 OSLO/C=NO/unstructuredAddress=92683399/O=Telenor Norge AS/OU=MULTI-ALLOWED";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(subject);
        String result = CertificateRequestUtils.getDealerName(request);
        assertNotNull(result);
        assertFalse(result.equals(""));
    }

    @Test
    public void testGetDealerNameShouldBeValidSubject() {
        String subject = "/OU=0/unstructuredName=VEGARD-PC-TEST/L=Att: Kim Andr\\xC3\\xA9 Skjerpen, L6C, Snar\\xC3\\xB8yv 3 1331 Fornebu/C=NO/O=Telenor Norge AS/OU=MULTI-ALLOWED/ST=NO/unstructuredAddress=vegaasen@gmail.com/CN=375 - Test Online Forhandler";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(subject);
        String result = CertificateRequestUtils.getDealerName(request);
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("Test Online Forhandler", result);
    }

    @Test
    public void testGetDealerName_SubjectWithSigningTime() {
        String subject = "/OU=0/unstructuredName=TNA-01-3908-Vegaa/L=Att: Kim Andr\\xC3\\xA9 Skjerpen, L6C,  Snar\\xC3\\xB8yv 3 1331 Fornebu/C=NO/unstructuredAddress=92683399/O=Telenor Norge AS/OU=MULTI-ALLOWED/ST=NO/CN=375 - Test Online Forhandler/signingTime=1367300702564";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(subject);
        String result = CertificateRequestUtils.getDealerName(request);
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertEquals("Test Online Forhandler", result);
    }


    @Test
    public void testGetDealerIdShouldBeValidSubject() {
        String subject = "/OU=0/unstructuredName=VEGARD-PC-TEST/L=Att: Kim Andr\\xC3\\xA9 Skjerpen, L6C, Snar\\xC3\\xB8yv 3 1331 Fornebu/C=NO/O=Telenor Norge AS/OU=MULTI-ALLOWED/ST=NO/unstructuredAddress=vegaasen@gmail.com/CN=375 - Test Online Forhandler";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(subject);
        int result = CertificateRequestUtils.getDealerId(request);
        assertNotNull(result);
        assertTrue(result == 375);
    }

    @Test
    public void shouldGetIssuerFromHeader() {
        String issuerSubject = "/C=NO/O=Telenor Norge AS/OU=Symantec Trust Network/OU=Class 2 Managed PKI Individual Subscriber CA/CN=Telenor Norge AS OTL C";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_ISSUER_SUBJECT.toString()))
                .thenReturn(issuerSubject);
        String result = CertificateRequestUtils.getSubjectIssuer(request);
        assertNotNull(result);
        assertTrue(result.length() > 0);
        assertEquals(issuerSubject, result);
    }

    @Test
    public void shouldNotGetAnythingFromNulledRequest() {
        String result = CertificateRequestUtils.getSubjectIssuer(request);
        assertNotNull(result);
        assertEquals(result, "");
    }

    @Test
    public void shouldNotGetAnythingFromUndefinedHeader() {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_ISSUER_SUBJECT.toString()))
                .thenReturn("");
        String result = CertificateRequestUtils.getSubjectIssuer(request);
        assertNotNull(result);
        assertEquals(result, "");
    }

    @After
    public void tearDown() {
        attributes = null;
        parameters = null;
        request = null;
        session = null;
    }

}
