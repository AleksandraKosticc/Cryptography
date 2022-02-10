package cryptography;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import javafx.stage.FileChooser;

/**
 *
 * @author Aleksandra
 */
public class HelpFun {
    
    public static void moveFile(String fileName, String folderName) throws IOException {
        Path src = Paths.get(fileName); // fileName is the absolute path.
        Path dest = Paths.get(folderName); // folderName is the absolute path.
        
        Files.move(src, dest);
    }
    
    public static void configureFileChooser(final FileChooser fileChooser) {

        String parentPath = System.getProperty("user.dir");

        String other = parentPath + File.separator + "root" + File.separator + LoginFormController.controler.getUserName().getText();
        System.out.println(other);

        fileChooser.setInitialDirectory(
                new File(other)
        );
    }
    
}