package cryptography;

import com.jfoenix.controls.JFXComboBox;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
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
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.fxml.FXML;
import javafx.fxml.Initializable;
import javafx.geometry.Pos;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.stage.FileChooser;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import model.User;

import org.controlsfx.control.Notifications;

/**
 * FXML Controller class
 *
 * @author Aleksandra
 */
public class CreateTextFormController implements Initializable {

    final FileChooser fileChooser = new FileChooser();

    @FXML
    private TextArea textArea;
    @FXML
    private TextField titleText;
    @FXML
    private JFXComboBox<String> ComboBoxAlgoritham;
    @FXML
    private JFXComboBox<String> ComboBoxHash;

    private User user;
    private final ArrayList<User> users = new ArrayList<>();
    X509Certificate certificateCA;
    X509CRL CRL;

    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {
       
        ComboBoxAlgoritham.getItems().addAll("3DES", "AES-128", "AES-256");
        ComboBoxAlgoritham.getSelectionModel().selectFirst();
        ComboBoxHash.getItems().addAll("SHA-1", "SHA-256", "SHA-512");
        ComboBoxHash.getSelectionModel().selectFirst();

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
            if (!LoginFormController.controler.getUserName().getText().equals(tmp[0])) {

                User temp = new User();
                temp.setUsername(tmp[0]);
                temp.setFirstname(tmp[3]);
                temp.setPathCertificate("sertifikati/" + temp.getUsername() + ".crt");
                users.add(temp);
                System.out.println(users);
            } else {
                user = new User();
                user.setUsername(tmp[0]);
                user.setFirstname(tmp[3]);
                user.setPathCertificate("sertifikati/" + user.getUsername() + ".crt");
                users.add(user);
                System.out.println(users);
            }
        }
        FileInputStream korSert = null;
        try {

            korSert = new FileInputStream(user.getPathCertificate());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            user.setSertifikat((X509Certificate) cf.generateCertificate(korSert));
            FileInputStream finCA = new FileInputStream("rootCA/ca.crt");
            certificateCA = (X509Certificate) cf.generateCertificate(finCA);
            finCA.close();

            CRL = (X509CRL) cf.generateCRL(new FileInputStream("crl/crl.der"));
            CRL.verify(certificateCA.getPublicKey());
            if (CRL.isRevoked(user.getCertificate())) {
                throw new CRLException();

            }

            X509Certificate certificate = Certificate.generateCertificate(user.getPathCertificate());
            certificate.verify(certificateCA.getPublicKey());
            certificate.checkValidity(new Date());

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

        } catch (CertificateExpiredException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateNotYetValidException | FileNotFoundException | SignatureException | InvalidKeySpecException | CRLException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | IOException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        } finally {
            try {
                korSert.close();
            } catch (IOException ex) {
                Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    @FXML
    private void saveBtn(MouseEvent event) {

        if (titleText.getText().equals("")) {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Error")
                    .text("Unesite naziv tekstualne datoteke!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        } else {

            String titleFile = titleText.getText();
            String path = System.getProperty("user.dir") + "/root/" + LoginFormController.controler.getUserName().getText() + "/" + titleFile + ".txt";
            System.out.print(path);
            File ff = new File(path);

            String name = ff.getName();
            File file = new File(path);

            saveSystem(file, textArea.getText());

            String src = "root/" + user.getUsername() + "/" + user.getUsername() + "-" + name + ".bin";
            File srcFile = new File(src);

            if (!srcFile.exists()) {

                try {
                    encryptionRoot(path, user.getUsername(), (String) ComboBoxAlgoritham.getValue(), users, user.getUsername(), user.getUsername() + "-" + name + ".bin");
                    file.delete();

                } catch (IOException ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                }
                Image image = new Image("img/mooo.png");
                Notifications notification = Notifications.create()
                        .text("Uspješno kreiran dokument!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();

                titleText.setText("");
                textArea.setText("");
            } else {
                ff.delete();
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .text("Datoteka već postoji sa istim nazivom!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
            }
        }
    }

    @FXML
    private void editBtn(MouseEvent event) {

        HelpFun.configureFileChooser(fileChooser);

        fileChooser.setTitle("Select TXT Files");
        fileChooser.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("TXT Files", "*.bin"));
        File fileOpen = fileChooser.showOpenDialog(null);
        String[] posiljalac = fileOpen.getName().split("-");
        String[] dekDat = posiljalac[1].split("\\.");

        File srcFile = new File("root/" + user.getUsername() + "/" + dekDat[0] + "." + dekDat[1]);
        String src = "root/" + user.getUsername() + "/" + dekDat[0] + ".txt";

        try {
            boolean rez = decryptionRoot(fileOpen.getAbsolutePath(), posiljalac[0], users, user.getUsername(), dekDat[0] + "." + dekDat[1]);

            if (rez) {

                Scanner scanner = new Scanner(srcFile);
                try {
                    titleText.setText(srcFile.getName());
                    titleText.setText(titleText.getText().replace(".txt", ""));
                    while (scanner.hasNextLine()) {
                        textArea.appendText(scanner.nextLine() + "\n");
                    }
                } finally {
                    scanner.close();
                }
                fileOpen.delete();
                srcFile.delete();
            }

        } catch (FileNotFoundException ex) {
            Logger.getLogger(CreateTextFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(CreateTextFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException | ParseException ex) {
            Logger.getLogger(CreateTextFormController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void saveSystem(File file, String content) {

        try {
            PrintWriter printWriter = new PrintWriter(file);
            printWriter.write(content);
            printWriter.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(CreateTextFormController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    
    public void encryptionRoot(String path, String receiver, String algoritam, ArrayList<User> list, String sender, String cryptFile) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, Exception {
        User receiverUser = null;
        for (User u : list) {
            if (u.getUsername().equals(receiver)) {
                receiverUser = u;
            }
        }

        FileInputStream korSert;
        try {
            korSert = new FileInputStream(receiverUser.getPathCertificate());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            receiverUser.setSertifikat((X509Certificate) cf.generateCertificate(korSert));
        } catch (FileNotFoundException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        }

        boolean keyUsage[] = Certificate.generateCertificate(receiverUser.getPathCertificate()).getKeyUsage();
        if (keyUsage != null) {
            if (keyUsage[2] && keyUsage[3]) {

                File inputFile = new File(path);
                User senderUser = null;
                for (User u : list) {
                    if (u.getUsername().equals(sender)) {
                        senderUser = u;
                    }
                }

                byte potpis[] = null;
                boolean[] keyUsagePosiljalac = Certificate.generateCertificate(senderUser.getPathCertificate()).getKeyUsage();
                if (keyUsagePosiljalac[0]) {
                    potpis = createDigital(inputFile, senderUser);
                } else {
                    Image image = new Image("img/delete.png");
                    Notifications notification = Notifications.create()
                            .text("Vaš sertifikat se ne može koristiti za digitalno potpisivanje!")
                            .position(Pos.BOTTOM_RIGHT)
                            .graphic(new ImageView(image));
                    notification.darkStyle();
                    notification.show();
                    return;
                }

                BufferedOutputStream bos = null;
                BufferedInputStream bis = null;
                byte buffer[] = new byte[1024];
                try {
                    bos = new BufferedOutputStream(new FileOutputStream("potpis_i_plaintext.bin", true));
                    bos.write(potpis);
                    bos.flush();
                    int length;
                    bis = new BufferedInputStream(new FileInputStream(path));
                    while ((length = bis.read(buffer, 0, buffer.length)) != -1) {

                        bos.write(buffer, 0, length);
                    }
                    bos.flush();

                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    try {
                        bos.close();
                        bis.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                SecretKey key = null;
                File symmetricallyEncryptedFile = null;
                try {
                    key = Crypto.genericSymmetricKey(algoritam);
                    symmetricallyEncryptedFile = Crypto.encryptFileSymmetricAlg("potpis_i_plaintext.bin", algoritam, key);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Date date = new Date();
                DateFormat df = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                String dateString = df.format(date);

                String pot = null;
                switch (ComboBoxHash.getValue()) {
                    case "SHA-256":
                        pot = ComboBoxHash.getValue();
                        break;
                    case "SHA-512":
                        pot = ComboBoxHash.getValue();
                        break;
                    default:
                        pot = ComboBoxHash.getValue();
                        break;
                }

                PublicKey publicKeyReceiver = Certificate.generateCertificate(receiverUser.getPathCertificate()).getPublicKey();
                FileOutputStream fos = null;
                FileInputStream fis = null;
                String alg = null;
                if (algoritam.contains("AES")) {
                    String[] tmp = algoritam.split("-");
                    alg = tmp[0];
                } else {
                    alg = "DESede";
                }
                try {
                    Cipher cipher = Cipher.getInstance("RSA");
                    cipher.init(Cipher.ENCRYPT_MODE, publicKeyReceiver);
                    byte encryptedPrivateKey[] = cipher.doFinal(key.getEncoded());
                    byte encryptedAlgorithm[] = cipher.doFinal(alg.getBytes());
                    byte cipheredDate[] = cipher.doFinal(dateString.getBytes());
                    byte encryptedSignature[] = cipher.doFinal(pot.getBytes());

                    fos = new FileOutputStream(new File("root/" + receiverUser.getUsername() + "/" + cryptFile), true);
                    fos.write(cipheredDate);
                    fos.write(encryptedPrivateKey);
                    fos.write(encryptedAlgorithm);
                    fos.write(encryptedSignature);
                    fos.flush();

                    byte buffer2[] = new byte[1024];
                    fis = new FileInputStream(symmetricallyEncryptedFile);
                    int len;
                    while ((len = fis.read(buffer2)) != -1) {

                        fos.write(buffer2, 0, len);
                    }
                    fos.flush();

                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                } catch (FileNotFoundException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        fos.close();
                        fis.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            } else {
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .title("Greška")
                        .text("Ključ dobijen iz sertifikata primaoca se ne smije koristiti za kriptovanje podataka i simetričnog ključa.")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
            }
        } else {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Ključ dobijen iz sertifikata primaoca se ne smije koristiti za kriptovanje podataka i simetričnog ključa.")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        }

        File f1 = new File("potpis_i_plaintext.bin");
        f1.delete();
        File f2 = new File("simetricnoKripvotavanaDat.bin");
        f2.delete();
    }

    private byte[] createDigital(File ulazniFajl, User user) throws Exception {
        if (ComboBoxHash.getValue().equals("SHA-256")) {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(user.getPrivateKey());
            byte[] buffer = new byte[1024];
            FileInputStream fis = new FileInputStream(ulazniFajl);
            int len;
            while ((len = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, len);
            }

            byte[] dgst = signature.sign();
            fis.close();
            return dgst;
        } else if (ComboBoxHash.getValue().equals("SHA-512")) {
            Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initSign(user.getPrivateKey());
            byte[] buffer = new byte[1024];
            FileInputStream fis = new FileInputStream(ulazniFajl);
            int len;
            while ((len = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, len);
            }
            byte[] dgst = signature.sign();
            fis.close();
            return dgst;
        } else {
            Signature signature = Signature.getInstance("SHA1withRSA");
            signature.initSign(user.getPrivateKey());
            byte[] buffer = new byte[1024];
            FileInputStream fis = new FileInputStream(ulazniFajl);
            int len;
            while ((len = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, len);
            }
            byte[] dgst = signature.sign();
            fis.close();
            return dgst;
        }
    }

    public boolean decryptionRoot(String path, String sender, ArrayList<User> lista, String receiver, String nazivDekriptovaneDatoteke) throws ParseException, IOException, CertificateException {

        User receiverUser = null;
        User senderUser = null;
        for (User u : lista) {
            if (u.getUsername().equals(receiver)) {
                receiverUser = u;
            }
            if (u.getUsername().equals(sender)) {
                senderUser = u;
            }
        }

        boolean usage[] = Certificate.generateCertificate(receiverUser.getPathCertificate()).getKeyUsage();
        if (usage[2] && usage[3]) {

            File ulazniFajl = new File(path);
            byte sifrovaniDatum[] = new byte[256];
            byte sifrovaniSimetricniKljuc[] = new byte[256];
            byte sifrovaniAlgoritam[] = new byte[256];
            byte sifrovaniPotpis[] = new byte[256];

            FileInputStream fis = null;
            Date datum = null;
            try {
                fis = new FileInputStream(ulazniFajl);
                fis.read(sifrovaniDatum);

                PrivateKey privatniKljucprimaoca = receiverUser.getPrivateKey();
                Cipher cipher;

                cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, privatniKljucprimaoca);
                byte datumBytes[] = cipher.doFinal(sifrovaniDatum);
                String dateString = new String(datumBytes);
                DateFormat df = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                datum = df.parse(dateString);

                fis.read(sifrovaniSimetricniKljuc);
                fis.read(sifrovaniAlgoritam);
                fis.read(sifrovaniPotpis);

                byte[] simetricniKljuc = cipher.doFinal(sifrovaniSimetricniKljuc);
                byte[] algoritam = cipher.doFinal(sifrovaniAlgoritam);
                byte[] pot = cipher.doFinal(sifrovaniPotpis);
                String algString = new String(algoritam);
                String algoritamString = algString.trim();
                String potString = new String(pot);
                String potpisString = potString.trim();

                File kriptovanaDatotekaSimetricnimAlgoritmom = new File("Dek1KriptovanaSimetricnim.bin");
                FileOutputStream fos = new FileOutputStream(kriptovanaDatotekaSimetricnimAlgoritmom, true);
                byte buffer2[] = new byte[1024];
                int len;
                while ((len = fis.read(buffer2)) != -1) {
                    fos.write(buffer2, 0, len);
                    fos.flush();
                }
                fos.close();
                fis.close();
                SecretKey simetricniKljuc1 = (SecretKey) new SecretKeySpec(simetricniKljuc, 0, simetricniKljuc.length, algoritamString);

                File dekriptovanaDat = Crypto.decryptFileSymmetricAlg(kriptovanaDatotekaSimetricnimAlgoritmom, algoritamString, simetricniKljuc1);

                byte potpis[] = new byte[256];
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(dekriptovanaDat));
                bis.read(potpis);

                File plainTextDekriptovanaDat = new File("root/" + receiverUser.getUsername() + "/" + nazivDekriptovaneDatoteke);
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(plainTextDekriptovanaDat, true));
                int len2;
                byte buffer3[] = new byte[1024];
                while ((len2 = bis.read(buffer3, 0, buffer3.length)) != -1) {
                    bos.write(buffer3, 0, len2);
                }
                bos.flush();
                bos.close();
                bis.close();

                //verifikacija potpisa//
                boolean usage2[] = Certificate.generateCertificate(senderUser.getPathCertificate()).getKeyUsage();
                if (usage2[0]) {
                    Signature signature = null;
                    if (potpisString.equals("SHA-256")) {
                        signature = Signature.getInstance("SHA256withRSA");
                    } else {
                        signature = Signature.getInstance("SHA1withRSA");
                    }

                    signature.initVerify(Certificate.generateCertificate(senderUser.getPathCertificate()).getPublicKey());

                    byte buffer[] = new byte[1024];
                    BufferedInputStream bis2 = new BufferedInputStream(new FileInputStream(plainTextDekriptovanaDat));
                    while ((len = bis2.read(buffer)) != -1) {
                        try {
                            signature.update(buffer, 0, len);
                        } catch (SignatureException e) {
                            e.printStackTrace();
                        }
                    }
                    bis2.close();

                    try {
                        if (!signature.verify(potpis)) {
                            fis.close();
                            Image image = new Image("img/delete.png");
                            Notifications notification = Notifications.create()
                                    .title("Greška")
                                    .text("Potpis nije uspjesno verifikovan!")
                                    .position(Pos.BOTTOM_RIGHT)
                                    .graphic(new ImageView(image));
                            notification.darkStyle();
                            notification.show();
                            return false;
                        }
                    } catch (SignatureException e) {
                        //e.printStackTrace();
                    }
                } else {
                    Image image = new Image("img/delete.png");
                    Notifications notification = Notifications.create()
                            .title("Greška")
                            .text("Korisnik koji je primio datoteku ne moze da utvrdi integritet jer u sertifikatu primaoca nije definisan odgovarajuci keyUsage!")
                            .position(Pos.BOTTOM_RIGHT)
                            .graphic(new ImageView(image));
                    notification.darkStyle();
                    notification.show();
                    return false;
                }

            } catch (IllegalBlockSizeException e) {
                //e.printStackTrace();
            } catch (BadPaddingException e) {
                fis.close();
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .title("Greška")
                        .text("Poruka je izmijenjena!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
                return false;
                //e.printStackTrace();
            } catch (InvalidKeyException e) {
                //    e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                //    e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                //    e.printStackTrace();
            } catch (FileNotFoundException e) {
                //    e.printStackTrace();
            } catch (IOException e) {
                //    e.printStackTrace();
            } catch (ParseException e) {
                //    e.printStackTrace();
            }
        } else {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Korisnik ne moze da dekriptuje primljenu datoteku jer nema odgovarajuci keyUsage u svom sertifikatu!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
            return false;
        }
        File f1 = new File("Dek1KriptovanaSimetricnim.bin");
        f1.delete();
        File f2 = new File("dekriptovanaDat.bin");
        f2.delete();
        return true;
    }
}