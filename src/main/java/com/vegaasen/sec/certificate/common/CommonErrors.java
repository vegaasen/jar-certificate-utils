package com.vegaasen.sec.certificate.common;

public final class CommonErrors {
    public static final String E_CERTIFICATE_HAS_NOT_BEEN_INITIALIZED =
            "Certificate has not been initialized.";
    public static final String E_CERTIFICATE_NO_SUBJECT_SUPPLIED =
            "No subject supplied.";
    public static final String E_UNABLE_TO_RETRIEVE_THUMBPRINT_FROM_CERTIFICATE =
            "Unable to retrieve thumbprint from certificate.";
    public static final String E_UNABLE_TO_GENERATE_FINGERPRINT =
            "Unable to generate thumbprint of certificate.";
    public static final String E_NO_REQUEST_OBJECT_PRESENT =
            "No request object present. Could it be null?";
    public static final String E_ILLEGAL_FORMAT_ON_SUBJECT_SUPPLIED =
            "Format supplied was illegal. Please try to apply convertToLegalSubjectFormat()";
    public static final String E_NO_SUCH_HEADER =
            "No such header.";

    public static final String E_HEADER_ELEMENT_NOT_PRESENT = "HeaderElement {%s} not present on request. ";

    //FieldRelated
    public static final int
            NOT_FOUND = -1,
            WRONG_FORMAT = -2,
            MISSING_NUMERICAL = -3;

    public static final String
            EMPTY = "";

    private CommonErrors() {
    }
}
