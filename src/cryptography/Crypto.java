package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 *
 * @author Aleksandra
 */
public class Crypto {

    public static File encryptFileSymmetricAlg(String ulaznaDat, String algoritam, SecretKey key) throws Exception {

        Cipher cipher = null;
        if (algoritam.contains("AES")) {
            cipher = Cipher.getInstance("AES");  
        } else {
            cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        }

        cipher.init(Cipher.ENCRYPT_MODE, key);

        File simetricnoKriptovanaDat = new File("simetricnoKripvotavanaDat.bin");
        FileInputStream fis = new FileInputStream(new File(ulaznaDat));
        CipherOutputStream cos = new CipherOutputStream(new FileOutputStream(simetricnoKriptovanaDat, true), cipher);
        byte[] buffer = new byte[1024];
        int len;
        while ((len = fis.read(buffer)) != -1) {

            cos.write(buffer, 0, len);
            cos.flush();

        }
        cos.close();
        fis.close();

        return simetricnoKriptovanaDat;
    }

    public static File decryptFileSymmetricAlg(File ulazniFajl, String algoritam, SecretKey simetricniKljuc) {
        Cipher cipher = null;
        File dekriptovanaDat = null;
        try {

            if (algoritam.contains("AES")) {
                cipher = Cipher.getInstance("AES");
            } else {
                cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
            }

            cipher.init(Cipher.DECRYPT_MODE, simetricniKljuc);

            dekriptovanaDat = new File("dekriptovanaDat.bin");
            FileOutputStream fos = new FileOutputStream(dekriptovanaDat);

            CipherInputStream cis = new CipherInputStream(new FileInputStream(ulazniFajl), cipher);

            byte[] buffer = new byte[1024];
            int len;
            while ((len = cis.read(buffer)) != -1) {
                fos.write(buffer, 0, len);
                fos.flush();
            }
            cis.close();
            fos.close();

        } catch (NoSuchAlgorithmException e) {
            //   e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            //  e.printStackTrace();
        } catch (InvalidKeyException e) {
            //e.printStackTrace();
        } catch (FileNotFoundException e) {
            //e.printStackTrace();
        } catch (IOException e) {
            //e.printStackTrace();
        }
        return dekriptovanaDat;
    }

    public static SecretKey genericSymmetricKey(String algoritam) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = null;

        if (algoritam.equals("3DES")) {
            keyGen = KeyGenerator.getInstance("DESede");
        } else if (algoritam.equals("AES-128")) {
            keyGen = KeyGenerator.getInstance("AES");
        } else {
            keyGen = KeyGenerator.getInstance("AES");
        }

        if (algoritam.equals("AES-128")) {
            keyGen.init(128);
        } else if (algoritam.equals("3DES")) {
            keyGen.init(168);
        } else {
            keyGen.init(256);
        }

        SecretKey key = keyGen.generateKey();
        return key;
    }

    public static String hash(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02X", b));
            }
            password = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return password;
    }

    public static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[4];
        random.nextBytes(salt);
        return salt;
    }

    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static String bytesToStringHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
