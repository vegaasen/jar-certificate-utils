package com.vegaasen.sec.certificate.crypt;

import com.vegaasen.sec.certificate.abs.UtilsAbstract;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Simple utilities that is related to certificates
 *
 * @author vegaasen
 * @version 1.0-SNAPSHOT
 * @since 1.0-SNAPSHOT
 */
public class CryptUtils extends UtilsAbstract {

    /**
     * Digest a string with an encryption type
     *
     * @param str            the string to digest
     * @param encryptionType the digest-type
     * @return a byte array containing the digested string
     * @throws NullPointerException _
     */
    public static byte[] convertToDigest(final byte[] str, final EncryptionType encryptionType)
            throws NullPointerException {
        if (str != null && encryptionType != null) {
            if (str.length > 0) {
                try {
                    MessageDigest messageDigest = MessageDigest.getInstance(encryptionType.toString());
                    messageDigest.update(str);
                    return messageDigest.digest();
                } catch (NoSuchAlgorithmException e) {
                    throw new UnsupportedOperationException("Could not process item.");
                }
            }
            return str;
        }
        throw new NullPointerException("The string or Encryptiontype was undefined.");
    }

    /**
     * Convert a string using the base64 alg., or decrypt an existing string.
     *
     * @param string the string to enhance
     * @param encode true|false == true=encrypt | false=decrypt
     * @return a byte array containing the resulted string
     * @throws Exception
     */
    public static byte[] base64EncDec(final String string, boolean encode)
            throws Exception {
        if (string != null && !string.equals("")) {
            //missing...
        }
        throw new NullPointerException("The string or Encryptiontype was undefined.");
    }

    /*
     * Helper-enum for some of the most known Encryption-types out there.
     *
     */
    public enum EncryptionType {
        MD_5("MD5"),
        SHA_1("SHA-1"),
        MD_2("MD2"),
        BASE_64("base64");

        private String encryptionType;

        EncryptionType(String encryptionType) {
            this.encryptionType = encryptionType;
        }

        @Override
        public String toString() {
            return encryptionType;
        }
    }
}
