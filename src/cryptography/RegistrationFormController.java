package cryptography;

import com.jfoenix.controls.JFXPasswordField;
import com.jfoenix.controls.JFXTextField;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
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
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.input.MouseEvent;
import javafx.scene.layout.AnchorPane;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import org.controlsfx.control.Notifications;

/**
 * FXML Controller class
 *
 * @author Aleksandra
 */
public class RegistrationFormController implements Initializable {

    @FXML
    private JFXTextField username;
    @FXML
    private JFXPasswordField password;
    @FXML
    private JFXTextField certificatePath;
    @FXML
    private JFXTextField privateKeyPath;
    @FXML
    private AnchorPane anchorPane;

    File file = new File("users.txt");

    /**
     * Initializes the controller class.
     */
    @Override
    public void initialize(URL url, ResourceBundle rb) {
        // TODO
        String name = username.getText();

    }

    @FXML
    private void signButton(ActionEvent event) throws NoSuchAlgorithmException {

        registration(username.getText(), password.getText(), certificatePath.getText(), privateKeyPath.getText());
    }

    @FXML
    private void handlePathPrivateKey(MouseEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Upload Private key");

        FileChooser.ExtensionFilter extFilterDER
                = new FileChooser.ExtensionFilter("Private key (*.der)", "*.der");

        fileChooser.getExtensionFilters().addAll(extFilterDER);
        File selected = fileChooser.showOpenDialog(null);

        if (selected != null) {
            privateKeyPath.setText(selected.getAbsolutePath());
        }
    }

    @FXML
    private void handlePath(MouseEvent event) {
        FileChooser fileChooser = new FileChooser();
        fileChooser.setTitle("Upload Certificate");

        FileChooser.ExtensionFilter extFilterCRT
                = new FileChooser.ExtensionFilter("Certicifate (*.crt)", "*.crt");

        fileChooser.getExtensionFilters().addAll(extFilterCRT);
        File selected = fileChooser.showOpenDialog(null);

        if (selected != null) {
            certificatePath.setText(selected.getAbsolutePath());
        }
    }

    @FXML
    private void handleClose(MouseEvent event) {
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

    private void registration(String name, String passwd, String pathCertificate, String pathKey) throws NoSuchAlgorithmException {

        if (certificatePath.getText().equals("") || privateKeyPath.getText().equals("")
                || username.getText().equals("") || password.getText().equals("")
                || certificatePath.getText().equals("")) {

            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Unesite sva polja!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        } else {

            byte[] salt = Crypto.getSalt();
            String s = Crypto.bytesToStringHex(salt);

            String hashLoz = Crypto.hash(s + passwd);
            try {

                BufferedWriter bw = new BufferedWriter(new FileWriter(file, true));
                bw.append('\n');
                bw.append(name + "#" + s + "#" + hashLoz + "#" + name);
                bw.close();
            } catch (IOException ex) {
                //ex.printStackTrace();
                Image image = new Image("img/delete.png");
                Notifications notification = Notifications.create()
                        .title("Greška")
                        .text("Datoteka ne postoji!")
                        .position(Pos.BOTTOM_RIGHT)
                        .graphic(new ImageView(image));
                notification.darkStyle();
                notification.show();
            }

            String pathUserFolders = (System.getProperty("user.dir").toString() + "\\user_folders\\" + name);
            File file = new File(pathUserFolders);
            file.mkdir();
            String pathRoot = (System.getProperty("user.dir").toString() + "\\root\\" + name);
            File file1 = new File(pathRoot);
            file1.mkdir();
            String path = pathCertificate;
            try {
                final File myFile = new File(path);
                if (myFile.renameTo(new File(System.getProperty("user.dir") + "/sertifikati/" + myFile.getName()))) {
                    System.out.println("Move!");
                } else {
                    System.out.println("File is failed!");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            String path2 = pathKey;
            try {
                final File myFileKey = new File(path2);
                if (myFileKey.renameTo(new File(System.getProperty("user.dir") + "/user_folders/" + name + "/" + myFileKey.getName()))) {
                    System.out.println("Moveee!");
                } else {
                    System.out.println("File is failed to move!");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            Image image = new Image("img/mooo.png");
            Notifications notification = Notifications.create()
                    .text("Uspješna registracija!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();

            certificatePath.setText("");
            privateKeyPath.setText("");
            password.setText("");
            username.setText("");
        }
    }
}
