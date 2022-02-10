package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.geometry.Pos;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import model.User;
import org.controlsfx.control.Notifications;

/**
 *
 * @author Aleksandra
 */
public class Certificate {

    private User user;
    private final ArrayList<User> users = new ArrayList<>();
    X509Certificate certificateCA;
    X509CRL CRL;
    FileInputStream korSert = null;

    public int checkCertificate() {

        File file = new File("users.txt");
        List<String> lines = Collections.emptyList();
        try {
            lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
        Iterator<String> itr = lines.iterator();
        while (itr.hasNext()) {
            String line = (String) itr.next();
            String[] tmp = line.split("#");
            if (LoginFormController.controler.getUserName().getText().equals(tmp[0])) {
                user = new User();
                user.setUsername(tmp[0]);
                user.setPathCertificate("sertifikati/" + user.getUsername() + ".crt");
                users.add(user);
                break;
            }
        }

        if (!new File(user.getPathCertificate()).exists()) {
            return -2;
        }

        try {
            ////////////////POSTAVLJANJE SERTIFIKATA///////////////////////
            korSert = new FileInputStream(user.getPathCertificate());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            user.setSertifikat((X509Certificate) cf.generateCertificate(korSert));
            FileInputStream finCA = new FileInputStream("rootCA/ca.crt");
            certificateCA = (X509Certificate) cf.generateCertificate(finCA);
            finCA.close();

            ///////////////////CRL PROVJERA////////////////////////////////
            CRL = (X509CRL) cf.generateCRL(new FileInputStream("crl/crl.der"));
            CRL.verify(certificateCA.getPublicKey());
            if (CRL.isRevoked(user.getCertificate())) {
                throw new CRLException();

            }
            ////////////////PROVJERA SERTIFIKATA////////////////////////////
            X509Certificate certificate = generateCertificate(user.getPathCertificate());
            certificate.verify(certificateCA.getPublicKey());
            certificate.checkValidity(new Date());

            ///////////////PRIVATNI KLJUC//////////////////////////////////
            user.setPathUserFolder("user_folders/" + user.getUsername() + "/");
            File privKey = new File(user.getPathUserFolder() + "private.der");

            if (privKey.exists()) {
                byte[] privBytes = Files.readAllBytes(Paths.get(privKey.getPath()));
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                user.setPrivateKey(kf.generatePrivate(spec));
            } else {
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .title("Greška")
                        .text("Vaš privatni ključ je premješten ili obrisan sa sistema.")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
                throw new InvalidKeySpecException();
            }
        } catch (SignatureException ex) {
            return -5;
        } catch (CertificateNotYetValidException ex) {
            return -4;
        } catch (CertificateExpiredException ex) {
            return -3;
        } catch (FileNotFoundException ex) {
            return -2;
        } catch (CRLException ex) {
            return -1;
        } catch (java.security.cert.CertificateException | IOException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeySpecException ex) {
            Logger.getLogger(Certificate.class.getName()).log(Level.SEVERE, null, ex);
        }
        return 1;
    }

    public static X509Certificate generateCertificate(String pathCertificate) throws IOException, CertificateException {
        FileInputStream fin = new FileInputStream(pathCertificate);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) cf.generateCertificate(fin);
        fin.close();
        return certificate;
    }
}
