package com.vegaasen.sec.certificate.cert;

import com.vegaasen.sec.certificate.common.CertificateFields;
import com.vegaasen.sec.certificate.http.SslHeaders;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import java.security.cert.CertificateException;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Simple test-case that tests the functionality when the user only have Strings, and no PEM-enabled x509Certificate present
 *
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 * @since 1.0-SNAPSHOT
 */

@RunWith(PowerMockRunner.class)
@PrepareForTest({SslHeaders.class})
public class CertificateUtilsByStringTest {

    private static final String
            CERTIFICATE_SUBJECT = "C=ZA, ST=Western Cape, L=Cape Town, O=Thawte Consulting cc," +
            "OU=Certification Services Division,OU=blablabla," +
            "CN=Thawte Server CA,emailAddress=server-certs@thawte.com",

    CLAVIS_375 = "ST=NO,CN=375 - Test Online Forhandler,OU=MULTI-ALLOWED,O=Telenor Norge AS,emailAddress=vegaasen@gmail.com,C=NO,L=Att: Kim Andre Skjerpen\\, L6C\\, Snarøyv 3 1331 Fornebu,unstructuredName=TNA-00-0003,OU=0",
            CLAVIS_7777 = "C=NO,ST=1017556515 - TNA-01-3806 - 134484,L=Snarøyv 30\\, L3f 1331 SNARØYA,O=Telenor,OU=t524555,CN=7777 - Kundeservice Fornebu,ST=Huey - Dewey - Louie",
            CLAVIS_1723 = "C=NO,ST=1017556515 - TNA-01-3806 - 134484,L=Snarøyv 30\\, L3f 1331 SNARØYA,O=Telenor,OU=t524555,CN=1723-Reitan Servicehandel Norge AS,ST=Huey - Dewey - Louie",
            CLAVIS_WRONG_FORMAT = "C=NO,ST=1017556515 - TNA-01-3806 - 134484,L=Snarøyv 30\\, L3f 1331 SNARØYA,O=Telenor,CN=Kundeservice Fornebu,OU=t524555,ST=Huey - Dewey - Louie",
            CLAVIS_0442 = "ST=NO,CN=0442 - Some test Dealer,OU=MULTI-ALLOWED,O=Telenor Norge AS,emailAddress=vegaasen@gmail.com,C=NO,L=Att: Vegard Aasen\\, L6C\\, Snarøyv 3 1331 Fornebu,unstructuredName=TNA-00-0003,OU=0",
            CLAVIS_NO_FIELD = "C=NO,ST=1017556515 - TNA-01-3806 - 134484,L=Snarøyv 30\\, L3f 1331 SNARØYA,O=Telenor,OU=t524555,ST=Huey - Dewey - Louie",
            CLAVIS_ILLEGAL_FORMAT = "/C=NO/ST=1017556515 - TNA-01-3806 - 134484/L=Snar\\\\xF8yv 30, L3f 1331 SNAR\\\\xD8YA/O=Telenor/OU=t\n" +
                    "524555/CN=7777 - Kundeservice Fornebu/ST=Huey - Dewey - Louie",

    CLAVIS_OTL_SUPPORT = "OU = MULTI-ALLOWED,O = Telenor Norge AS, Unstructured Address = 92683399, C = NO, L = Stranden 57 250 Oslo, Unstructured Name = TNA-01-3908-Vegaa, OU = 888112642, CN = OTLSUP - OTL Testforhandler",
            CLAVIS_OTL_WEB = "OU = MULTI-ALLOWED,O = Telenor Norge AS, Unstructured Address = 92683399, C = NO, L = Stranden 57 250 Oslo, Unstructured Name = TNA-01-3908-Vegaa, OU = 888112642, CN = OTLWEB - Hello Norway AS",

    ENGIMA_375_SPACED = "C=NO, ST=1147044227 - TNA-06-5777 - 166405, L=PB 414 1331 Fornebu, O=Telenor, OU=t516553, CN=375 - Test Online Forhandler",
            ENIGMA_STRANGE_FORMAT = "OU=0/unstructuredName=TNA-01-3909, L=Att: Kim Andr&#xC3&#xA9 Skjerpen, L6C,  Snar&#xC3&#xB8yv 3 1331 Fornebu, C=NO, O=Telenor Norge AS, OU=MULTI-ALLOWED, ST=NO, CN=375 - Test Online Forhandler";

    @Test
    public void testGetCertificateField_shouldFindCNField() {
        List<String> fields = CertificateUtils.getCertificateField(CERTIFICATE_SUBJECT, CertificateFields.COMMON_NAME);
        assertTrue(!fields.isEmpty());
        assertTrue(fields.get(0) != null);
        assertTrue(fields.contains("Thawte Server CA"));
    }

    @Test
    public void testGetCertificateField_shouldFindFields() {
        List<String> fields = CertificateUtils.getCertificateField(CERTIFICATE_SUBJECT, CertificateFields.ORGANIZATION_UNIT);
        assertNotNull(fields);
        assertTrue(fields.size() != 0);
        assertTrue(fields.contains("blablabla"));
        assertTrue(fields.contains("Certification Services Division"));
    }

    @Test
    public void testGetDealerName_OTLSUPPORT() throws CertificateException {
        final String expectedDealerName = "OTL Testforhandler";
        String dealerName = CertificateUtils.getDealerName(CLAVIS_OTL_SUPPORT);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerName_OTLWEB() throws CertificateException {
        final String expectedDealerName = "Hello Norway AS";
        String dealerName = CertificateUtils.getDealerName(CLAVIS_OTL_WEB);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerName_1723_Reitan() throws CertificateException {
        final String expectedDealerName = "Reitan Servicehandel Norge AS";
        String dealerName = CertificateUtils.getDealerName(CLAVIS_1723);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerName_375() throws CertificateException {
        final String expectedDealerName = "Test Online Forhandler";
        String dealerName = CertificateUtils.getDealerName(CLAVIS_375);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerName_7777() throws CertificateException {
        final String expectedDealerName = "Kundeservice Fornebu";
        String dealerName = CertificateUtils.getDealerName(CLAVIS_7777);
        assertNotNull(dealerName);
        assertTrue(!dealerName.isEmpty());
        assertEquals(expectedDealerName, dealerName);
    }

    @Test
    public void testGetDealerId_Subject_375() throws CertificateException {
        int dealerId = CertificateUtils.getDealerId(CLAVIS_375);
        assertNotNull(dealerId);
        assertTrue(dealerId != 0);
        assertEquals(375, dealerId);
    }

    @Test
    public void testGetDealerId_Subject_7777() throws CertificateException {
        int dealerId = CertificateUtils.getDealerId(CLAVIS_7777);
        assertNotNull(dealerId);
        assertTrue(dealerId != 0);
        assertEquals(7777, dealerId);
    }

    @Test
    public void testGetDealerId_Subject_375_Enigma_Style() throws CertificateException {
        int dealerId = CertificateUtils.getDealerId(ENGIMA_375_SPACED);
        assertNotNull(dealerId);
        assertTrue(dealerId != 0);
        assertEquals(375, dealerId);
    }

    @Test
    public void testGetDealerId_Subject_0442() throws CertificateException {
        final String commonName = CertificateUtils.getCommonName(CLAVIS_0442);
        assertTrue("Using 0442 from CN=" + commonName, commonName != null);
        int dealerId = CertificateUtils.getDealerId(CLAVIS_0442);
        assertNotNull(dealerId);
        assertTrue(dealerId != 0);
        assertTrue(dealerId > 0);
        assertEquals("Expecting 442, getting: " + dealerId, 442, dealerId);
    }

    @Test(expected = CertificateException.class)
    public void testGetDealerId_FromCommonNameOnly_shouldFail() throws CertificateException {
        final String expectedCommonName = "0442 - Some test Dealer";
        final String commonName = CertificateUtils.getCommonName(CLAVIS_0442);
        assertTrue(commonName != null);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);

        CertificateUtils.getDealerId(commonName);
    }

    @Test
    public void testGetDealerId_FromCommonNameOnly() throws CertificateException {
        final String expectedCommonName = "0442 - Some test Dealer";
        final String commonName = CertificateUtils.getCommonName(CLAVIS_0442);
        assertTrue(commonName != null);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);

        Integer dealerId = CertificateUtils.getDealerIdFromCNFieldValue(commonName);
        assertNotNull(dealerId);
        assertEquals(new Integer(442), dealerId);
    }

    @Test
    public void testGetDealerId_FromStrangeFormat() throws CertificateException {
        final String commonName = "CN=0442 - Some test Dealer";
        Integer dealerId = CertificateUtils.getDealerIdFromCNFieldValue(commonName);
        assertNotNull(dealerId);
        assertEquals(new Integer(442), dealerId);
    }

    @Test
    public void testGetDealerId_Subject_NoSuchField() throws CertificateException {
        Integer dealerId = CertificateUtils.getDealerId(CLAVIS_NO_FIELD);
        assertNotNull(dealerId);
        assertTrue(dealerId != 0);
        assertEquals(new Integer(-3), dealerId);
    }

    @Test
    public void testGetDealerId_Subject_WrongFormat() throws CertificateException {
        int dealerId = CertificateUtils.getDealerId(CLAVIS_WRONG_FORMAT);
        assertNotNull(dealerId);
        assertTrue(dealerId != 0);
        assertEquals(-3, dealerId);
    }

    @Test
    public void testGetCommonNameFromSubjectField() throws CertificateException {
        final String expectedCommonName = "Thawte Server CA";
        String commonName = CertificateUtils.getCommonName(CERTIFICATE_SUBJECT);
        assertNotNull(commonName);
        assertTrue(!commonName.equals(""));
        assertEquals(expectedCommonName, commonName);
    }

    @Test
    public void testConvertInvalidString_shouldBeValid() throws CertificateException {
        final String expectedSubject = "C=NO,ST=1017556515 - TNA-01-3806 - 134484,L=Snar\\\\xF8yv 30\\, L3f 1331 SNAR\\\\xD8YA,O=Telenor,OU=t\n" +
                "524555,CN=7777 - Kundeservice Fornebu,ST=Huey - Dewey - Louie";
        String legalSubject = CertificateUtils.convertToLegalSubjectFormat(CLAVIS_ILLEGAL_FORMAT, "/");
        assertNotNull(legalSubject);
        assertTrue(!legalSubject.equals(""));
        assertEquals(expectedSubject, legalSubject);
    }

    @Test
    public void testGetCountry() throws CertificateException {
        final String expected = "NO";
        String country = CertificateUtils.getCountry(CLAVIS_375);
        assertNotNull(country);
        assertTrue(!country.equals(""));
        assertEquals(expected, country);
    }

    @Test
    public void testGetLegality() throws CertificateException {
        final String expected = "Snarøyv 30, L3f 1331 SNARØYA";
        String result = CertificateUtils.getLocality(CLAVIS_7777);
        assertNotNull(result);
        assertTrue(!result.equals(""));
        assertEquals(expected, result);
    }

    @Test
    public void testGetEmailAddress() throws CertificateException {
        final String expected = "null";
        String email = CertificateUtils.getEmailAddress(CLAVIS_375);
        assertNotNull(email);
        assertTrue(!email.equals(""));
        assertEquals(expected, email);
    }

    @Test
    public void testGetCommonName_StrangeFormat() throws CertificateException {
        String format = CertificateUtils.getCommonName(ENIGMA_STRANGE_FORMAT);
        assertNotNull(format);
        assertEquals("null", format);
    }

    @Test(expected = CertificateException.class)
    public void testConvertInvalidString_shouldFailWithException() throws CertificateException {
        CertificateUtils.convertToLegalSubjectFormat(CLAVIS_ILLEGAL_FORMAT, ",");
    }

    @Test
    public void testConvertInvalidString_shouldNotCompleteConversion_returnUnchangedSubject() throws CertificateException {
        String legalSubject = CertificateUtils.convertToLegalSubjectFormat(CLAVIS_ILLEGAL_FORMAT, ".");
        assertNotNull(legalSubject);
        assertTrue(!legalSubject.equals(""));
        assertEquals(CLAVIS_ILLEGAL_FORMAT, legalSubject);
    }

}
