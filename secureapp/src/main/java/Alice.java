import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import keys.KeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.util.jar.JarException;

public class Alice {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        Security.addProvider(new BouncyCastleProvider());
        PublicKey alicePub = null;
        PrivateKey alicePriv = null;
        PublicKey bobPub = null;
        X509Certificate aliceCert = null;
        try{

             alicePub = KeyUtils.readPublicKey("alice");
             alicePriv = KeyUtils.readPrivateKey("alice");
             bobPub = KeyUtils.readPublicKey("bob");
             aliceCert = KeyUtils.readX509Certificate("alice");
             System.out.println("HERE: "+ aliceCert.toString());
        }
        catch (Exception e){
            System.out.println(e);
        }

        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            //RECEIVE MESSAGES FROM BOB
            PublicKey finalBobPub = bobPub;
            Thread bobListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();

                        // Decrypt with the recipient's public key
                        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        decryptCipher.init(Cipher.DECRYPT_MODE, finalBobPub);
                        byte[] decryptedBytes = decryptCipher.doFinal(Base64.decode(receivedMessage));

                        int digestLength = 32; // For SHA-256
                        int messageLength = decryptedBytes.length - digestLength;
                        byte[] receivedM = new byte[messageLength];
                        byte[] receivedDigest = new byte[digestLength];
                        System.arraycopy(decryptedBytes, 0, receivedM, 0, messageLength);
                        System.arraycopy(decryptedBytes, messageLength, receivedDigest, 0, digestLength);

                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] receivedMessageDigest = md.digest(receivedM);

                        boolean isDigestValid = MessageDigest.isEqual(receivedDigest, receivedMessageDigest);

                        if (isDigestValid) {
                            String decryptedMessage = new String(receivedM, "UTF-8");

                            System.out.println("Bob: "+ decryptedMessage);
                        } else {
                            System.out.println("Message Digest is NOT Valid");
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    throw new RuntimeException(e);
                } catch (IllegalBlockSizeException e) {
                    throw new RuntimeException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException(e);
                } catch (BadPaddingException e) {
                    throw new RuntimeException(e);
                } catch (InvalidKeyException e) {
                    throw new RuntimeException(e);
                }
            });
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                // Load the image from a file into a byte array
                File imageFile = new File("secureapp/twitter-logo.png");
                byte[] imageBytes = Files.readAllBytes(imageFile.toPath());

                // Calculate the SHA-256 hash of the image data
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                byte[] imageDigest = md.digest(imageBytes);

                String textMessage = scanner.nextLine();

                //Combine image and text
                byte[] delimiter = "#DELIMITER#".getBytes(StandardCharsets.UTF_8);
                byte[] combinedData = new byte[imageBytes.length + delimiter.length + textMessage.getBytes().length];
                System.arraycopy(imageBytes, 0, combinedData, 0, imageBytes.length);
                System.arraycopy(delimiter, 0, combinedData, imageBytes.length, delimiter.length);
                System.arraycopy(textMessage.getBytes(), 0, combinedData, imageBytes.length, textMessage.getBytes().length);

                byte[] combinedDataDigest = md.digest(combinedData);

                byte[] data = new byte[combinedData.length + combinedDataDigest.length];
                System.arraycopy(combinedData, 0, data, 0, combinedData.length);
                System.arraycopy(combinedDataDigest, 0, data, combinedData.length, combinedDataDigest.length);

                //2. ENCRYPT HASHED MESSAGE WITH PRIVATE KEY
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, alicePriv);
                byte[] privEncryptedMessage = cipher.doFinal(data);//encrypts

                if (!textMessage.isEmpty()) {
                    dataOutputStream.writeUTF(Base64.toBase64String(privEncryptedMessage));
                    System.out.println("sent:"+privEncryptedMessage.toString());
                }
                if (textMessage.equalsIgnoreCase("exit")) {
                    break;
                }
            }

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
