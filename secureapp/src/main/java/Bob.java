import keys.KeyUtils;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

public class Bob {
    public static void main(String[] args) {
        PublicKey bobPub = null;
        PrivateKey bobPriv = null;
        PublicKey alicePub = null;


        Scanner scanner = new Scanner(System.in);
        int port = 5001;
        AtomicReference<byte[]> sessionKeyRef = new AtomicReference<>();

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream.writeUTF("bob");

            //ALL KEYS
            bobPub = KeyUtils.readPublicKey("bob");
            bobPriv = KeyUtils.readPrivateKey("bob");
            alicePub = KeyUtils.readPublicKey("alice");

            boolean isFirstConnected = dataInputStream.readBoolean();
            System.out.println("First to connect: "+ isFirstConnected);

            if (isFirstConnected) {
                System.out.println("CREATING SECRET KEY");

                // Initialize the RSA engine
                RSAKeyParameters rsaPublicKey = (RSAKeyParameters) PublicKeyFactory.createKey(alicePub.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(true, rsaPublicKey);

                // Generate a random session key.
                SecureRandom secureRandom = new SecureRandom();
                byte[] sessionKey = new byte[16];
                secureRandom.nextBytes(sessionKey);
                System.out.println("sessionkey: "+ Arrays.toString(sessionKey));

                // Encrypt the session key with Bob's public key using RSA with PKCS1Padding
                byte[] encryptedSessionKey = rsaEngine.processBlock(sessionKey, 0, sessionKey.length);

                // Encode the session key using base64
                String base64SessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
                System.out.println("Base64-encoded Session Key: " + base64SessionKey);

                dataOutputStream.writeUTF(base64SessionKey);

                sessionKeyRef.set(sessionKey);
            }
            else if (!isFirstConnected){
                System.out.println("RECEIVING SECRET KEY");
                // Read the base64-encoded session key as a string
                String base64EncryptedSessionKey = dataInputStream.readUTF();

                // Decode the Base64 string back into a byte array
                byte[] encryptedSessionKey = Base64.getDecoder().decode(base64EncryptedSessionKey);

                // Initialize the RSA engine with Bob's private key
                RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPriv.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(false, rsaPrivateKey);

                // Decrypt the encrypted session key
                byte[] sessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
                System.out.println("DECRYPTED key " + Arrays.toString(sessionKey));

                sessionKeyRef.set(sessionKey);

            }

            //RECEIVE MESSAGES FROM ALICE
            PublicKey finalAlicePub = alicePub;
            Thread aliceListener = new Thread(() -> {
                try {
                    while (true) {
                        System.out.println("got");
                        String base64EncryptedMessage = dataInputStream.readUTF();
                        int digestLength = 256; // For SHA-256
                        // Decode the Base64 string back into a byte array
                        byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);
                        System.out.println("0");
                        try {
                            byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key
                            System.out.println("1");
                            if (sessionKey != null) {
                                int messageLength = encryptedMessage.length - digestLength;
                                byte[] receivedM = new byte[messageLength];
                                byte[] receivedDigest = new byte[digestLength];
                                System.arraycopy(encryptedMessage, 0, receivedM, 0, messageLength);
                                System.arraycopy(encryptedMessage, messageLength, receivedDigest, 0, digestLength);
                                System.out.println("2");

                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                                byte[] decryptedMessage = cipher.doFinal(receivedM);
                                System.out.println(decryptedMessage.toString());
                                System.out.println(receivedM.toString());

                                // Decrypt digest with the sender's public key
                                Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                decryptCipher.init(Cipher.DECRYPT_MODE, finalAlicePub);
                                byte[] decryptedDigest = decryptCipher.doFinal(receivedDigest);

                                MessageDigest md = MessageDigest.getInstance("SHA-1");
                                byte[] receivedMessageDigest = md.digest(decryptedMessage);
                                System.out.println("3");
                                boolean isDigestValid = MessageDigest.isEqual(receivedMessageDigest, decryptedDigest);

                                if (isDigestValid) {
                                    // Process the decrypted message as needed
                                    System.out.println("4");
                                    System.out.println("5");
//                                    if (delimiterPosition != -1)
                                    //{
                                        // Split the message into imageBytes and captionBytes
                                    String stringM =new String(decryptedMessage, StandardCharsets.UTF_8);
                                    System.out.println(6);
//                                        String decryptedMessageString = new String(captionBytes, "UTF-8");
                                    System.out.println("Decrypted message: " + stringM);

                                    String[] lines = stringM.split(" DELIMITER ");

                                    System.out.println("Decrypted message: " + lines[0]);
                                    System.out.println("Decrypted message: " + lines[1]);
                                    saveDecodedDataToDesktop(lines[0], "test");
//                                    } else {
//                                        System.out.println("DECRYPTION ERROR!");
//                                    }
                                }

                            }
                            else{
                                System.out.println("NO SESSION KEY");
                            }
                        }
                        catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }
            });
            aliceListener.start();

            //SEND MESSAGES TO ALICE
            while (true) {
                String message = scanner.nextLine();
                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(message);

                // Check so it doesn't send empty messages
                if (!message.isEmpty()) {
                    try {
                        byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                        if (sessionKey != null) {
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                            byte[] digest = md.digest(messageBytes);

                            //2. ENCRYPT DIGEST WITH PRIVATE KEY
                            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            rsaCipher.init(Cipher.ENCRYPT_MODE, bobPriv);
                            byte[] privEncryptedDigest = rsaCipher.doFinal(digest);
                            byte[] data = new byte[messageBytes.length + privEncryptedDigest.length];

                            System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                            System.arraycopy(privEncryptedDigest, 0, data, messageBytes.length, privEncryptedDigest.length);

                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                            byte[] encryptedMessage = cipher.doFinal(data);

                            // Encode the entire encryptedMessageBytes
                            String Base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                            dataOutputStream.writeUTF(Base64EncryptedMessage);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                    if (message.equalsIgnoreCase("exit")) {
                        break;
                    }
                }
                }
            socket.close();
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }

    public static boolean saveDecodedDataToDesktop(String base64Image, String fileName) {
        try {
            // Decode the Base64 image data
            byte[] decodedImageBytes = Base64.getDecoder().decode(base64Image);

            // Create a BufferedImage from the decoded byte array
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedImageBytes);
            BufferedImage image = ImageIO.read(bais);

            // Save the decrypted image to the specified output path
            ImageIO.write(image, "jpg", new File("test.jpg"));
        } catch (IOException e) {
            e.printStackTrace();
        }

        return false; // Data save operation failed
    }
    public static byte[] decompressData(byte[] compressedData) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(compressedData);
             GZIPInputStream gzipInputStream = new GZIPInputStream(bais);
             ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = gzipInputStream.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            return baos.toByteArray();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}

