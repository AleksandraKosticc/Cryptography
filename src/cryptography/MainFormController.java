package cryptography;

import com.jfoenix.controls.JFXComboBox;
import java.awt.Desktop;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
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
public class MainFormController implements Initializable {

    @FXML
    private AnchorPane anchorPane;
    @FXML
    private Label labelaKor;
    @FXML
    private ComboBox<String> comboKript;
    @FXML
    private ComboBox<String> comboPotpis;
    @FXML
    private ComboBox<String> comboPrimaoc;
    @FXML
    private ComboBox<String> comboSharedFile;
    @FXML
    private JFXComboBox<String> comboRoot;
    @FXML
    private ComboBox<String> comboBoxEncRoot;
    @FXML
    private ComboBox<String> comboBoxHashRoot;
    @FXML
    private TextField pathUploadRoot;
    @FXML
    private TextField path;

    private User user;
    private final ArrayList<User> users = new ArrayList<>();
    X509Certificate certificateCA;
    X509CRL CRL;

    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {

        FileInputStream korSert = null;

        try {

            // TODO
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
                    comboPrimaoc.getItems().add(tmp[0]);
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

            ////////////////POSTAVLJANJE SERTIFIKATA///////////////////////
            korSert = new FileInputStream(user.getPathCertificate());
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            user.setSertifikat((X509Certificate) cf.generateCertificate(korSert));
            FileInputStream finCA = new FileInputStream("rootCA/ca.crt");
            certificateCA = (X509Certificate) cf.generateCertificate(finCA);
            finCA.close();

            ///////////////////CRL PROVJERA////////////////////////////
            CRL = (X509CRL) cf.generateCRL(new FileInputStream("crl/crl.der"));
            CRL.verify(certificateCA.getPublicKey());
            if (CRL.isRevoked(user.getCertificate())) {
                throw new CRLException();

            }

            ////////////////PROVJERA SERTIFIKATA////////////////////////////
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
                        .text("Vaš privatni ključ je premješten ili obrisan sa sistema!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
                throw new InvalidKeySpecException();
            }

            comboPrimaoc.setPromptText("Izaberi");
            labelaKor.setText(LoginFormController.controler.getUserName().getText());
            System.out.println("TRENUTNI KORISNIK: " + LoginFormController.controler.getUserName().getText());
            comboKript.getItems().addAll("AES-128", "AES-256", "3DES");
            comboKript.setPromptText("Izaberi");
            comboPotpis.getItems().addAll("SHA-1", "SHA-256", "SHA-512");
            comboPotpis.setPromptText("Izaberi");
            comboBoxEncRoot.getItems().addAll("Izaberi", "3DES", "AES-128", "AES-256");
            comboBoxEncRoot.getSelectionModel().selectFirst();
            comboBoxHashRoot.getItems().addAll("Izaberi", "SHA-1", "SHA-256", "SHA-512");
            comboBoxHashRoot.getSelectionModel().selectFirst();

            File brPor = new File("shared");
            comboSharedFile.setPromptText("Izaberi datoteku");
            for (String tmp : brPor.list()) {
                if (tmp.contains(".bin")) {
                    comboSharedFile.getItems().add(tmp);
                }
            }

            File root = new File("root/" + user.getUsername());
            comboRoot.setPromptText("Izaberi datoteku");
            for (String tmp : root.list()) {
                if (tmp.contains(".bin")) {
                    comboRoot.getItems().add(tmp);
                }
            }

        } catch (CertificateExpiredException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateNotYetValidException | FileNotFoundException | InvalidKeySpecException | CRLException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | IOException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
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
    private void handlePosaljiButton(ActionEvent event) {
        if (path.getText() == null || comboKript.getValue() == null || comboPotpis.getValue() == null || comboPrimaoc.getValue() == null) {

            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Unesite sva polja!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        } else {

            File file = new File(path.getText());
            String naziv = file.getName();
            String src = "shared/" + user.getUsername() + "-" + naziv + ".bin";
            File srcFile = new File(src);

            if (!srcFile.exists()) {
                try {
                    enkripcija(path.getText(), (String) comboPrimaoc.getValue(), (String) comboKript.getValue(), users, user.getUsername(), user.getUsername() + "-" + naziv + ".bin");
                } catch (IOException ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else {
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .text("Datoteka već postoji!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
            }
        }
        path.setText("");

        File root = new File("shared/");
        comboSharedFile.setPromptText("Izaberi poruku");
        comboSharedFile.getItems().removeAll(comboSharedFile.getItems());
        for (String tmp : root.list()) {
            comboSharedFile.getItems().add(tmp);
        }
    }

    @FXML
    private void handleSearchButton(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Upload File");
        FileChooser.ExtensionFilter extFilterALL
                = new FileChooser.ExtensionFilter("All Files", "*.JPG", "*.jpg", "*.JPEG", "*.jpeg",
                        "*.PDF", "*.pdf", "*.PNG", "*.png", "*.TXT", "*.txt", "*.DOCX", "*.docx");
        FileChooser.ExtensionFilter extFilterJPG
                = new FileChooser.ExtensionFilter("JPG files (*.jpg)", "*.JPG", "*.jpg", "*.JPEG", "*.jpeg");
        FileChooser.ExtensionFilter extFilterPDF
                = new FileChooser.ExtensionFilter("Adobe PDF files (*.pdf)", "*.PDF", "*.pdf");
        FileChooser.ExtensionFilter extFilterPNG
                = new FileChooser.ExtensionFilter("PNG files (*.png)", "*.PNG", "*.png");
        FileChooser.ExtensionFilter extFilterTXT
                = new FileChooser.ExtensionFilter("Text (*.txt)", "*.TXT", "*.txt");
        FileChooser.ExtensionFilter extFilterDOCX
                = new FileChooser.ExtensionFilter("Word documents (*.docx)", "*.DOCX", "*.docx");

        fileChooser.getExtensionFilters().addAll(extFilterALL, extFilterJPG, extFilterPDF, extFilterPNG, extFilterTXT, extFilterDOCX);
        File selected = fileChooser.showOpenDialog(null);

        if (selected != null) {
            path.setText(selected.getAbsolutePath());

        }
    }

    @FXML
    private void handleDekPorukuButton(ActionEvent event) {
        if (comboSharedFile.getValue() != null) {
            File file = new File("shared/" + (String) comboSharedFile.getValue());
            String[] posiljalac = file.getName().split("-");
            String[] dekDat = posiljalac[1].split("\\.");

            try {
                boolean rez = dekripcija(file.getAbsolutePath(), posiljalac[0], users, user.getUsername(), dekDat[0] + "." + dekDat[1]);
                if (rez) {

                    File srcFile = new File("shared/" + dekDat[0] + "." + dekDat[1]);
                    String src = "shared/" + dekDat[0] + "." + dekDat[1];
                    String dest = System.getProperty("user.home") + "/Desktop/" + dekDat[0] + "." + dekDat[1];

                    try {
                        HelpFun.moveFile(src, dest);

                        file.delete();

                        Image image = new Image("img/mooo.png");
                        Notifications notification = Notifications.create()
                                .text("Uspješno preuzeta datoteka!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();

                    } catch (IOException e) {
                        srcFile.delete();

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .text("Datoteka već postoji!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                    }
                } else {
                    File f1 = new File("Dek1KriptovanaSimetricnim.bin");
                    f1.delete();
                    File f2 = new File("dekriptovanaDat.bin");
                    f2.delete();
                }

            } catch (ParseException | IOException | CertificateException ex) {
                Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .text("Izaberite datoteku!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        }

        File root = new File("shared/");
        comboSharedFile.setPromptText("Izaberi poruku");
        comboSharedFile.getItems().removeAll(comboSharedFile.getItems());
        for (String tmp : root.list()) {
            comboSharedFile.getItems().add(tmp);
        }
    }

    @FXML
    private void handleOpenButton(ActionEvent event) {
        if (comboRoot.getValue() != null) {
            File file = new File("root/" + user.getUsername() + "/" + (String) comboRoot.getValue());

            String[] posiljalac = file.getName().split("-");
            String[] dekDat = posiljalac[1].split("\\.");
            File srcFile = new File("root/" + user.getUsername() + "/" + dekDat[0] + "." + dekDat[1]);

            try {
                boolean res = decryptionRoot(file.getAbsolutePath(), posiljalac[0], users, user.getUsername(), dekDat[0] + "." + dekDat[1]);
                if (res) {

                    String src = "root/" + user.getUsername() + "/" + dekDat[0] + "." + dekDat[1];
                    File fileOpen = new File(src);

                    try {
                        Desktop.getDesktop().open(fileOpen);
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }

                } else {
                    Image image = new Image("img/delete.png");
                    Notifications notification = Notifications.create()
                            .title("Greška")
                            .text("Dogodila se greška prilikom dekripcije.")
                            .position(Pos.BOTTOM_RIGHT)
                            .graphic(new ImageView(image));
                    notification.darkStyle();
                    notification.show();
                }
            } catch (ParseException | IOException | CertificateException ex) {
                Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
            }
        } else {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Izaberi datoteku.")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        }
    }

    @FXML
    private void handleUploadButton(ActionEvent event) {

        if (pathUploadRoot.getText().equals("") || comboBoxEncRoot.getValue().equals("Izaberi") || comboBoxHashRoot.getValue().equals("Izaberi")) {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Unesite sva polja!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        } else {
            File file = new File(pathUploadRoot.getText());
            String naziv = file.getName();
            String src = "root/" + user.getUsername() + "/" + user.getUsername() + "-" + naziv + ".bin";
            File srcFile = new File(src);

            if (!srcFile.exists()) {
                try {
                    encryptionRoot(pathUploadRoot.getText(), user.getUsername(), (String) comboBoxEncRoot.getValue(), users, user.getUsername(), user.getUsername() + "-" + naziv + ".bin");

                } catch (IOException ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                } catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                } catch (Exception ex) {
                    Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
                }
            } else {
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .text("Datoteka već postoji!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
            }
        }
        pathUploadRoot.setText("");

        File root = new File("root/" + user.getUsername());
        comboRoot.setPromptText("Izaberi poruku");
        comboRoot.getItems().removeAll(comboRoot.getItems());
        for (String tmp : root.list()) {
            if (tmp.contains(".bin")) {
                comboRoot.getItems().add(tmp);
            }
        }
    }

    @FXML
    private void handleDownloadButton(ActionEvent event) throws InterruptedException {
        if (comboRoot.getValue() != null) {
            File file = new File("root/" + user.getUsername() + "/" + (String) comboRoot.getValue());

            String[] posiljalac = file.getName().split("-");
            String[] dekDat = posiljalac[1].split("\\.");

            try {
                boolean rez = decryptionRoot(file.getAbsolutePath(), posiljalac[0], users, user.getUsername(), dekDat[0] + "." + dekDat[1]);
                if (rez) {
                    String src = "root/" + user.getUsername() + "/" + dekDat[0] + "." + dekDat[1];
                    File srcFile = new File(src);
                    String dest = System.getProperty("user.home") + "/Desktop/" + dekDat[0] + "." + dekDat[1];

                    try {
                        HelpFun.moveFile(src, dest);

                        file.delete();

                        Image image = new Image("img/mooo.png");
                        Notifications notification = Notifications.create()
                                .text("Uspješno preuzeta datoteka!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();

                    } catch (IOException e) {
                        srcFile.delete();

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .text("Datoteka već postoji!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                    }
                }
            } catch (ParseException | IOException | CertificateException ex) {
                Logger.getLogger(MainFormController.class.getName()).log(Level.SEVERE, null, ex);
            }

        } else {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Izaberi datoteku.")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        }

        File root = new File("root/" + user.getUsername());
        comboRoot.setPromptText("Izaberi poruku");
        comboRoot.getItems().removeAll(comboRoot.getItems());
        for (String tmp : root.list()) {
            if (tmp.contains(".bin")) {
                comboRoot.getItems().add(tmp);
            }
        }
    }

    @FXML
    private void handleChooseButtonRoot(ActionEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Upload File");
        FileChooser.ExtensionFilter extFilterALL
                = new FileChooser.ExtensionFilter("All Files", "*.JPG", "*.jpg", "*.JPEG", "*.jpeg",
                        "*.PDF", "*.pdf", "*.PNG", "*.png", "*.TXT", "*.txt", "*.DOCX", "*.docx");
        FileChooser.ExtensionFilter extFilterJPG
                = new FileChooser.ExtensionFilter("JPG files (*.jpg)", "*.JPG", "*.jpg", "*.JPEG", "*.jpeg");
        FileChooser.ExtensionFilter extFilterPDF
                = new FileChooser.ExtensionFilter("Adobe PDF files (*.pdf)", "*.PDF", "*.pdf");
        FileChooser.ExtensionFilter extFilterPNG
                = new FileChooser.ExtensionFilter("PNG files (*.png)", "*.PNG", "*.png");
        FileChooser.ExtensionFilter extFilterTXT
                = new FileChooser.ExtensionFilter("Text (*.txt)", "*.TXT", "*.txt");
        FileChooser.ExtensionFilter extFilterDOCX
                = new FileChooser.ExtensionFilter("Word documents (*.docx)", "*.DOCX", "*.docx");

        fileChooser.getExtensionFilters().addAll(extFilterALL, extFilterJPG, extFilterPDF, extFilterPNG, extFilterTXT, extFilterDOCX);
        File selected = fileChooser.showOpenDialog(null);

        if (selected != null) {
            pathUploadRoot.setText(selected.getAbsolutePath());
        }
    }

    @FXML
    private void handleNewButton(ActionEvent event) throws IOException {
        FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/CreateTextForm.fxml"));
        Parent root = loader.load();
        Stage stage = new Stage();

        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.setResizable(false);
        stage.show();
    }

    @FXML
    private void handleDeleteButton(ActionEvent event) {

        if (comboRoot.getValue() != null) {

            File file = new File("root/" + user.getUsername() + "/" + (String) comboRoot.getValue());
            file.delete();

            File root = new File("root/" + user.getUsername());
            comboRoot.setPromptText("Izaberi poruku");
            comboRoot.getItems().removeAll(comboRoot.getItems());
            for (String tmp : root.list()) {
                if (tmp.contains(".bin")) {
                    comboRoot.getItems().add(tmp);
                }
            }
            Image image = new Image("img/mooo.png");
            Notifications notification = Notifications.create()
                    .title("Obavještenje")
                    .text("Uspješno obrisana datoteka.")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        } else {
            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Izaberi datoteku!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        }
    }

    @FXML
    private void handleLogoutButton(MouseEvent event) {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/LoginForm.fxml"));
            Parent root = loader.load();
            Stage stage = new Stage();
            Scene scene = new Scene(root);
            stage.setScene(scene);
            stage.setTitle("Prijava");
            stage.setResizable(false);
            stage.show();
            LoginFormController.controler = (LoginFormController) loader.getController();
        } catch (IOException ex) {
            Logger.getLogger(LoginFormController.class.getName()).log(Level.SEVERE, null, ex);
        }
        Stage old = (Stage) anchorPane.getScene().getWindow();
        old.hide();
    }

    public void enkripcija(String path, String receiver, String algoritam, ArrayList<User> list, String sender, String cryptFile) throws CertificateException, IOException, NoSuchAlgorithmException, InvalidKeyException, Exception {
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
                    potpis = createDigitalSignature(inputFile, senderUser);
                } else {
                    Image image = new Image("img/delete.png");
                    Notifications notification = Notifications.create()
                            .title("Greška")
                            .text("Vaš sertifikat se ne može koristiti za digitalno potpisivanje.")
                            .position(Pos.BOTTOM_RIGHT)
                            .graphic(new ImageView(image));
                    notification.darkStyle();
                    notification.show();
                }

                BufferedOutputStream bos = null;
                BufferedInputStream bis = null;
                byte buffer[] = new byte[1024];
                try {
                    bos = new BufferedOutputStream(new FileOutputStream("potpis_i_plaintext.bin", true));
                    bos.write(potpis);
                    bos.flush();
                    int duzina;
                    bis = new BufferedInputStream(new FileInputStream(path));
                    while ((duzina = bis.read(buffer, 0, buffer.length)) != -1) {

                        bos.write(buffer, 0, duzina);
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
                switch (comboPotpis.getValue()) {
                    case "SHA-256":
                        pot = comboPotpis.getValue();
                        break;
                    case "SHA-1":
                        pot = comboPotpis.getValue();
                        break;
                    default:
                        pot = comboPotpis.getValue();
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

                    fos = new FileOutputStream(new File("shared/" + cryptFile), true);
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

                } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IOException e) {
                    e.printStackTrace();
                } finally {
                    try {
                        fos.close();
                        fis.close();
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                Image image = new Image("img/mooo.png");
                Notifications notification = Notifications.create()
                        .title("Obavještenje")
                        .text("Poruka poslata.")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
            } else {
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .title("Greška")
                        .text("Ključ dobijen iz sertifikata primaoca se ne smije koristiti za kriptovanje podataka i simetričnog ključa!")
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

        File brPor = new File("shared");
        comboSharedFile.setPromptText("Izaberi poruku");
        for (String tmp : brPor.list()) {
            comboSharedFile.getItems().add(tmp);
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
                File simetricnoKriptovanaDat = null;
                try {
                    key = Crypto.genericSymmetricKey(algoritam);
                    simetricnoKriptovanaDat = Crypto.encryptFileSymmetricAlg("potpis_i_plaintext.bin", algoritam, key);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                Date date = new Date();
                DateFormat df = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                String dateString = df.format(date);

                String pot = null;
                switch (comboBoxHashRoot.getValue()) {
                    case "SHA-256":
                        pot = comboBoxHashRoot.getValue();
                        break;
                    case "SHA-512":
                        pot = comboBoxHashRoot.getValue();
                        break;
                    default:
                        pot = comboBoxHashRoot.getValue();
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
                    fis = new FileInputStream(simetricnoKriptovanaDat);
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
        if (comboBoxHashRoot.getValue().equals("SHA-256")) {
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
        } else if (comboBoxHashRoot.getValue().equals("SHA-512")) {
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

    private byte[] createDigitalSignature(File ulazniFajl, User korisnik) throws Exception {
        if (comboPotpis.getValue().equals("SHA-256")) {
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(korisnik.getPrivateKey());
            byte[] buffer = new byte[1024];
            FileInputStream fis = new FileInputStream(ulazniFajl);
            int len;
            while ((len = fis.read(buffer)) != -1) {
                signature.update(buffer, 0, len);
            }

            byte[] dgst = signature.sign();
            fis.close();
            return dgst;
        } else if (comboPotpis.getValue().equals("SHA-512")) {
            Signature signature = Signature.getInstance("SHA512withRSA");
            signature.initSign(korisnik.getPrivateKey());
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
            signature.initSign(korisnik.getPrivateKey());
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

    public boolean dekripcija(String path, String sender, ArrayList<User> list, String receiver, String decryptFile) throws ParseException, IOException, CertificateException {
        User receiverUser = null;
        User senderUser = null;
        for (User u : list) {
            if (u.getUsername().equals(receiver)) {
                receiverUser = u;
            }
            if (u.getUsername().equals(sender)) {
                senderUser = u;
            }
        }

        boolean usage[] = Certificate.generateCertificate(receiverUser.getPathCertificate()).getKeyUsage();
        if (usage[2] && usage[3]) {

            File inputFile = new File(path);
            byte encryptedDate[] = new byte[256];
            byte encryptedSymmetricKey[] = new byte[256];
            byte encryptedAlg[] = new byte[256];
            byte encryptedSignature[] = new byte[256];

            FileInputStream fis = null;
            Date date = null;
            try {
                fis = new FileInputStream(inputFile);
                fis.read(encryptedDate);

                PrivateKey privateKeyReceiver = receiverUser.getPrivateKey();
                Cipher cipher;

                cipher = Cipher.getInstance("RSA");
                cipher.init(Cipher.DECRYPT_MODE, privateKeyReceiver);
                byte dateBytes[] = cipher.doFinal(encryptedDate);
                String dateString = new String(dateBytes);
                DateFormat df = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
                date = df.parse(dateString);

                fis.read(encryptedSymmetricKey);
                fis.read(encryptedAlg);
                fis.read(encryptedSignature);

                byte[] symmetricKey = cipher.doFinal(encryptedSymmetricKey);
                byte[] algorithm = cipher.doFinal(encryptedAlg);
                byte[] pot = cipher.doFinal(encryptedSignature);
                String algString = new String(algorithm);
                String algorithmString = algString.trim();
                String potString = new String(pot);
                String signatureString = potString.trim();

                File encryptedFileSymmetricAlgorithm = new File("Dek1KriptovanaSimetricnim.bin");
                FileOutputStream fos = new FileOutputStream(encryptedFileSymmetricAlgorithm, true);
                byte buffer2[] = new byte[1024];
                int len;
                while ((len = fis.read(buffer2)) != -1) {
                    fos.write(buffer2, 0, len);
                    fos.flush();
                }
                fos.close();
                fis.close();
                SecretKey simetricniKljuc1 = (SecretKey) new SecretKeySpec(symmetricKey, 0, symmetricKey.length, algorithmString);

                File decryptedDat = Crypto.decryptFileSymmetricAlg(encryptedFileSymmetricAlgorithm, algorithmString, simetricniKljuc1);

                byte potpis[] = new byte[256];
                BufferedInputStream bis = new BufferedInputStream(new FileInputStream(decryptedDat));
                bis.read(potpis);

                File plainTextDecryptedDat = new File("shared/" + decryptFile);
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(plainTextDecryptedDat, true));
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
                    if (signatureString.equals("SHA-256")) {
                        signature = Signature.getInstance("SHA256withRSA");
                    } else if (signatureString.equals("SHA-512")) {
                        signature = Signature.getInstance("SHA512withRSA");
                    } else {
                        signature = Signature.getInstance("SHA1withRSA");
                    }

                    signature.initVerify(Certificate.generateCertificate(senderUser.getPathCertificate()).getPublicKey()); //initVerify metoda inicijalizuje klasu Signature ali za verifikovanje potpisa, ne za kreiranje

                    byte buffer[] = new byte[1024];
                    BufferedInputStream bis2 = new BufferedInputStream(new FileInputStream(plainTextDecryptedDat));
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
                                    .text("Potpis nije uspjesno verifikovan. Doslo je do izmjene originalnog podatka!")
                                    .position(Pos.BOTTOM_RIGHT)
                                    .graphic(new ImageView(image));
                            notification.darkStyle();
                            notification.show();
                            return false;
                        }

                    } catch (SignatureException e) {
                        e.printStackTrace();
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
                        .text("Došlo je do greške!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
                return false;

            } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException | IOException | ParseException e) {
                e.printStackTrace();
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

    public boolean decryptionRoot(String path, String sender, ArrayList<User> list, String receiver, String decryptFile) throws ParseException, IOException, CertificateException {

        User receiverUser = null;
        User senderUser = null;
        for (User u : list) {
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
            byte encryptedSignature[] = new byte[256];

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
                fis.read(encryptedSignature);

                byte[] simetricniKljuc = cipher.doFinal(sifrovaniSimetricniKljuc);
                byte[] algoritam = cipher.doFinal(sifrovaniAlgoritam);
                byte[] pot = cipher.doFinal(encryptedSignature);
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

                File plainTextDekriptovanaDat = new File("root/" + receiverUser.getUsername() + "/" + decryptFile);
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(plainTextDekriptovanaDat, true));
                int len2;
                byte buffer3[] = new byte[1024];
                while ((len2 = bis.read(buffer3, 0, buffer3.length)) != -1) {
                    bos.write(buffer3, 0, len2);
                }
                bos.flush();
                bos.close();
                bis.close();

                //verifikacija potpisa/////////////////
                boolean usage2[] = Certificate.generateCertificate(senderUser.getPathCertificate()).getKeyUsage();
                if (usage2[0]) {

                    Signature signature = null;
                    if (potpisString.equals("SHA-256")) {
                        signature = Signature.getInstance("SHA256withRSA");
                    } else if (potpisString.equals("SHA-512")) {
                        signature = Signature.getInstance("SHA512withRSA");
                    } else {
                        signature = Signature.getInstance("SHA1withRSA");
                    }

                    signature.initVerify(Certificate.generateCertificate(senderUser.getPathCertificate()).getPublicKey()); //initVerify metoda inicijalizuje klasu Signature ali za verifikovanje potpisa, ne za kreiranje

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