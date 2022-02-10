package model;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 *
 * @author Aleksandra
 */
public class User {

    private String firstname;
    private String username;
    private String pathCertificate;
    private X509Certificate certificate;
    private String pathUserFolder;
    private PrivateKey privateKey;

    public User() {

    }

    public User(String firstname) {
        this.firstname = firstname;

    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getPathCertificate() {
        return pathCertificate;
    }

    public void setPathCertificate(String pathCertificate) {
        this.pathCertificate = pathCertificate;
    }

    public X509Certificate getCertificate() {
        return certificate;
    }

    public void setSertifikat(X509Certificate certificate) {
        this.certificate = certificate;
    }

    public String getPathUserFolder() {
        return pathUserFolder;
    }

    public void setPathUserFolder(String pathUserFolder) {
        this.pathUserFolder = pathUserFolder;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String toString() {
        return username;
    }
}
