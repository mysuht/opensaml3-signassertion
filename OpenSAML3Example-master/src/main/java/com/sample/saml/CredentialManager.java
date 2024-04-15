package com.sample.saml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.security.x509.X509Credential;

public class CredentialManager {

    private static final String CRT_FILE_PATH = "./credentials/mycertificate.crt";
    private static final String PK_FILE_PATH = "./credentials/pcks8key.der";

    static {
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        System.setProperty("com.sun.org.apache.xml.internal.security.ignoreLineBreaks", "true");
    }

    public static X509Credential loadCredential() {
        try {
            // Step 1: Read the Certificate File (.crt)
            X509Certificate cert = loadCertificate();

            // Step 2: Read the Private Key File (.der)
            PrivateKey privateKey = loadPrivatekey2();

            // Step 3: Create X509Credential
            //BasicX509Credential credential = new BasicX509Credential(cert, privateKey);
            BasicX509Credential credential = new BasicX509Credential(cert, privateKey);

            return credential;

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static X509Certificate loadCertificate() throws FileNotFoundException, CertificateException {
        FileInputStream crtFis = new FileInputStream(CRT_FILE_PATH);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(crtFis);
        return cert;
    }

    private static PrivateKey loadPrivatekey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream keyFis = new FileInputStream(PK_FILE_PATH);
        byte[] keyBytes = new byte[keyFis.available()];
        keyFis.read(keyBytes);
        keyFis.close();

        // Remove any occurrences of &#13; from the keyBytes
        String privateKeyString = new String(keyBytes, "UTF-8").replace("&#13;", "");
        byte[] cleanedKeyBytes = privateKeyString.getBytes("UTF-8");

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA"); // Assuming RSA key, adjust if needed
        PrivateKey privateKey = kf.generatePrivate(keySpec);
        return privateKey;
    }

    private static PrivateKey loadPrivatekey2() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        FileInputStream keyFis = new FileInputStream(PK_FILE_PATH);
        byte[] buf = new byte[keyFis.available()];
        keyFis.read(buf);
        keyFis.close();

        PKCS8EncodedKeySpec kspec = new PKCS8EncodedKeySpec(buf);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(kspec);
        return privateKey;
    }

//    public static X509Credential getCredential() {
//        try {
//            // Step 1: Read the Certificate File
//            X509Certificate cert = getX509Certificate();
//
//            // Step 3: Create X509Credential
//            BasicX509Credential credential = new BasicX509Credential(cert);
//
//            // Optionally, you can set additional properties for the credential
//            // credential.setPrivateKey(privateKey); // If you have the private key
//
//            return credential;
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            return null;
//        }
//    }

    public static X509Certificate getX509Certificate() throws FileNotFoundException, CertificateException {
        X509Certificate cert = loadCertificate();
        return cert;
    }

    public static X509Certificate loadPublicKey(X509Certificate crt) throws IOException, CertificateException {
        return crt;
    }

    // Example usage
    public static void main(String[] args) {
        X509Credential credential = loadCredential();

        if (credential != null) {
            System.out.println("Credential obtained successfully!");
        } else {
            System.out.println("Failed to obtain credential.");
        }
    }

    private void loadCredentialsFromCsrFile() {
        try {
             String password="jkzhsmzku";
            String alias="business" ;

            char[] pass=password.toCharArray();

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream fis = new FileInputStream("pathToFile/fileName.csr");
            ks.load(fis, pass);
            KeyStore.PrivateKeyEntry pkEntry = null;
            pkEntry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
            PrivateKey pk = pkEntry.getPrivateKey();
            X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
        }catch(Exception ex) {
            ex.printStackTrace();
        }
    }
}

