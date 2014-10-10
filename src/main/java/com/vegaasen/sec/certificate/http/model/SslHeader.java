package com.vegaasen.sec.certificate.http.model;

/**
 * errr
 */
public final class SslHeader {

    private String ssl_ClientCert_PEM;
    private String ssl_ClientCert_Fingerprint;
    private String ssl_ClientCert_Serial_Number;
    private String ssl_ClientCert_Subject;
    private String ssl_ClientCert_Issuer_Subject;
    private String ssl_ClientCert_Not_Before;
    private String ssl_ClientCert_Not_After;

    public String getSsl_ClientCert_PEM() {
        return ssl_ClientCert_PEM;
    }

    public void setSsl_ClientCert_PEM(String ssl_ClientCert_PEM) {
        this.ssl_ClientCert_PEM = ssl_ClientCert_PEM;
    }

    public String getSsl_ClientCert_Fingerprint() {
        return ssl_ClientCert_Fingerprint;
    }

    public void setSsl_ClientCert_Fingerprint(String ssl_ClientCert_Fingerprint) {
        this.ssl_ClientCert_Fingerprint = ssl_ClientCert_Fingerprint;
    }

    public String getSsl_ClientCert_Serial_Number() {
        return ssl_ClientCert_Serial_Number;
    }

    public void setSsl_ClientCert_Serial_Number(String ssl_ClientCert_Serial_Number) {
        this.ssl_ClientCert_Serial_Number = ssl_ClientCert_Serial_Number;
    }

    public String getSsl_ClientCert_Subject() {
        return ssl_ClientCert_Subject;
    }

    public void setSsl_ClientCert_Subject(String ssl_ClientCert_Subject) {
        this.ssl_ClientCert_Subject = ssl_ClientCert_Subject;
    }

    public String getSsl_ClientCert_Issuer_Subject() {
        return ssl_ClientCert_Issuer_Subject;
    }

    public void setSsl_ClientCert_Issuer_Subject(String ssl_ClientCert_Issuer_Subject) {
        this.ssl_ClientCert_Issuer_Subject = ssl_ClientCert_Issuer_Subject;
    }

    public String getSsl_ClientCert_Not_Before() {
        return ssl_ClientCert_Not_Before;
    }

    public void setSsl_ClientCert_Not_Before(String ssl_ClientCert_Not_Before) {
        this.ssl_ClientCert_Not_Before = ssl_ClientCert_Not_Before;
    }

    public String getSsl_ClientCert_Not_After() {
        return ssl_ClientCert_Not_After;
    }

    public void setSsl_ClientCert_Not_After(String ssl_ClientCert_Not_After) {
        this.ssl_ClientCert_Not_After = ssl_ClientCert_Not_After;
    }
}
