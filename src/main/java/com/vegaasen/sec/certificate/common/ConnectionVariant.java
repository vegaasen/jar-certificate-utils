package com.vegaasen.sec.certificate.common;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 * @since 3:58 PM
 */
public enum ConnectionVariant {
    HTTP(""), HTTPS("");

    private String url;

    private ConnectionVariant(String url) {
        this.url = url;
    }

    @Override
    public String toString() {
        return this.url;
    }
}
