package cryptography;

import com.jfoenix.controls.JFXPasswordField;
import com.jfoenix.controls.JFXTextField;
import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.ResourceBundle;
import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.fxml.Initializable;
import javafx.geometry.Pos;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.TextField;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;
import javafx.scene.layout.AnchorPane;
import javafx.stage.Stage;
import javafx.stage.StageStyle;
import org.controlsfx.control.Notifications;

/**
 *
 * @author Aleksandra
 */
public class LoginFormController implements Initializable {

    static LoginFormController controler;

    @FXML
    private JFXTextField username;
    @FXML
    private JFXPasswordField password;
    @FXML
    private AnchorPane anchorPane;

    @Override
    public void initialize(URL url, ResourceBundle rb) {
        
    }

    @FXML
    void HandleLoginButton(ActionEvent event) throws IOException {

        if (username.getText().equals("") || password.getText().equals("")) {

            Image image = new Image("img/delete.png");
            Notifications notification = Notifications.create()
                    .title("Greška")
                    .text("Unesite sva polja!")
                    .position(Pos.BOTTOM_RIGHT)
                    .graphic(new ImageView(image));
            notification.darkStyle();
            notification.show();
        } else {

            if (login(username.getText(), password.getText())) {
                switch (Cryptography.cert.checkCertificate()) {
                    case -7: {

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Korisnički certifikat ima pogrešan potpis!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case -6: {
                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Vaš sertifikat je povučen!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case -5: {

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Vaš sertifikat nije potpisan od strane odgovarajućeg CA tijela.")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case -4: {

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Vaš sertifikat nije validan!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case -3: {
                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Vaš sertifikat je istekao!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case -2: {

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Ne postoji fajl!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case -1: {

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Vaš sertifikat je povučen!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case 0: {

                        Image image = new Image("img/delete.png");
                        Notifications notification = Notifications.create()
                                .title("Greška")
                                .text("Pogrešno korisničko ime ili lozinka!")
                                .position(Pos.BOTTOM_RIGHT)
                                .graphic(new ImageView(image));
                        notification.darkStyle();
                        notification.show();
                        break;
                    }
                    case 1: {

                        FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/MainForm.fxml"));
                        Parent root = loader.load();
                        Stage stage = new Stage();
                        Stage current = (Stage) username.getScene().getWindow();
                        Scene scene = new Scene(root);
                        stage.setScene(scene);
                        stage.initStyle(StageStyle.TRANSPARENT);
                        stage.setResizable(false);
                        current.hide();
                        stage.show();
                    }
                }
            }
        }
    }

    @FXML
    private void createButton(ActionEvent event) throws IOException {

        FXMLLoader loader = new FXMLLoader(getClass().getResource("/view/RegistrationForm.fxml"));
        Parent root = loader.load();
        Stage stage = new Stage();
        Stage current = (Stage) username.getScene().getWindow();
        Scene scene = new Scene(root);
        stage.setScene(scene);
        stage.initStyle(StageStyle.TRANSPARENT);
        stage.setResizable(false);
        current.hide();
        stage.show();
    }

    public static boolean login(String username, String pass) {
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
            if (username.equals(tmp[0])) {
                String salt = tmp[1];
                String hashLoz = Crypto.hash(salt + pass);
                if (hashLoz.equals(tmp[2])) {
                    return true;
                }
            }
        }
        return false;
    }

    public TextField getUserName() {
        return username;
    }
}