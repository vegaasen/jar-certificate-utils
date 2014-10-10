package com.vegaasen.sec.certificate.http;

import com.vegaasen.sec.certificate.cert.CertificateUtils;
import com.vegaasen.sec.certificate.common.CertificateTestCommon;
import com.vegaasen.sec.certificate.http.model.SslHeader;
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
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import static org.easymock.EasyMock.expect;
import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.powermock.api.easymock.PowerMock.replayAll;
import static org.powermock.api.easymock.PowerMock.verifyAll;

/**
 * Requires the following VM-flag;
 * -XX:-UseSplitVerifier
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({SslHeaders.class})
@PowerMockIgnore("javax.security.*")
public class SslHeadersTest {

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
    public void testShouldGetHeaderReturn_value() {
        final String expectedHeaderValue = "ST=NO,CN=375 - Test Online Forhandler,OU=MULTI-ALLOWED,O=Telenor Norge AS,emailAddress=vegaasen@gmail.com,C=NO,L=Att: Kim AndrÃ© Skjerpen\\, L6C\\, SnarÃ¸yv 3 1331 Fornebu,unstructuredName=TNA-00-0003,OU=0";
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT.toString()))
                .thenReturn(expectedHeaderValue);

        String subjectHeader = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_SUBJECT);

        assertNotNull(subjectHeader);
    }

    @Test
    public void testShouldGetFullCertificateAsString() {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);

        String certAsPem = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM);
        assertNotNull(certAsPem);
        assertTrue(!certAsPem.equals(""));
        assertEquals(CertificateTestCommon.CERTIFICATE_CLAVIS_375, certAsPem);
    }

    @Test
    public void testShouldGetFullCertificateAsString_getCertificate() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);

        String certAsPem = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM);
        assertNotNull(certAsPem);

        X509Certificate certificate = (X509Certificate) CertificateUtils.getCertificateFromString(certAsPem, "");
        assertNotNull(certificate);
        assertTrue(certificate.getVersion() == 3);
    }

    @Test
    public void testShouldGetFullCertificateAsString_getCommonNameFromCertificate() throws CertificateException {
        when(request.getHeader(SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM.toString()))
                .thenReturn(CertificateTestCommon.CERTIFICATE_CLAVIS_375);

        String certAsPem = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_PEM);
        assertNotNull(certAsPem);

        X509Certificate certificate = (X509Certificate) CertificateUtils.getCertificateFromString(certAsPem, "");
        assertNotNull(certificate);

        final String expectedCommonName = "375 - Test Online Forhandler";
        String commonName = CertificateUtils.getCommonName_x509(certificate);
        assertNotNull(commonName);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);
    }

    @Test
    public void testShouldReturnEmptyString_noSuchHeader() {
        String returnedHeader = SslHeaders.getHeader(request, SslHeaders.CertificateHeader.SSL_CLIENTCERT_ISSUER_SUBJECT);
        assertNotNull(returnedHeader);
        assertEquals("", returnedHeader);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testShouldReturnEmptySslHeaderObject_noHeader_IllegalArgException() {
        SslHeader header = SslHeaders.getSSLHeaderFromRequest(request);
    }

    @Test
    public void testShouldFetchSomeHeaders_noHeadersFound() {
        Enumeration<String> headerElements = new Enumeration<String>() {
            @Override
            public boolean hasMoreElements() {
                return false;
            }

            @Override
            public String nextElement() {
                return null;
            }
        };
        when(request.getHeaderNames()).thenReturn(headerElements);
        SslHeader header = SslHeaders.getSSLHeaderFromRequest(request);
        assertNotNull(header);
    }

    @Test(expected = IllegalArgumentException.class)
    public void test_getSSLHeaderFromRequest_shouldReturnIllegalAE() {
        HttpServletRequest request = null;

        expect(sslHeaders.getSSLHeaderFromRequest(request)).andThrow(new IllegalArgumentException());

        replayAll();

        sslHeaders.getSSLHeaderFromRequest(request);

        verifyAll();
    }

    @After
    public void tearDown() {

    }

}
