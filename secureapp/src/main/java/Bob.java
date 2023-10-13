import keys.KeyUtils;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicReference;

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
            System.out.println("FIRST TO CONNECT: "+ isFirstConnected);

            if (isFirstConnected) {
                System.out.println("CREATING SESSION KEY");

                // Initialize the RSA engine
                RSAKeyParameters rsaPublicKey = (RSAKeyParameters) PublicKeyFactory.createKey(alicePub.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(true, rsaPublicKey);

                // Generate a random session key.
                SecureRandom secureRandom = new SecureRandom();
                byte[] sessionKey = new byte[16];
                secureRandom.nextBytes(sessionKey);

                // Encrypt the session key with Alice's public key using RSA with PKCS1Padding
                System.out.println("ENCRYPTING SESSION KEY WITH ALICE'S PUBLIC KEY");
                byte[] encryptedSessionKey = rsaEngine.processBlock(sessionKey, 0, sessionKey.length);

                // Encode the session key using base64
                System.out.println("ENCODING SESSION KEY");
                String base64SessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
                System.out.println("BASE64-ENCODED SESSION KEY: " + base64SessionKey);

                System.out.println("SENDING SESSION KEY TO ALICE");
                dataOutputStream.writeUTF(base64SessionKey);

                sessionKeyRef.set(sessionKey);
            }
            else if (!isFirstConnected){
                System.out.println("RECEIVING SESSION KEY");
                // Read the base64-encoded session key as a string
                String base64EncryptedSessionKey = dataInputStream.readUTF();

                // Decode the Base64 string back into a byte array
                System.out.println("DECODING SESSION KEY");
                byte[] encryptedSessionKey = Base64.getDecoder().decode(base64EncryptedSessionKey);

                // Initialize the RSA engine with Bob's private key
                RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPriv.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(false, rsaPrivateKey);

                // Decrypt the encrypted session key
                System.out.println("DECRYPTING SESSION KEY WITH BOB'S PRIVATE KEY");
                byte[] sessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);

                sessionKeyRef.set(sessionKey);

            }

            //RECEIVE MESSAGES FROM ALICE
            PublicKey finalAlicePub = alicePub;
            Thread aliceListener = new Thread(() -> {
                try {
                    while (true) {
                         String base64EncryptedMessage = dataInputStream.readUTF();
                        int digestLength = 256; // For SHA-256
                        // Decode the Base64 string back into a byte array
                        byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);
                        try {
                            byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                            System.out.println("DECRYPTING MESSAGE");
                            System.out.println("DECRYPTING DIGEST/HASH WITH BOB'S PUBLIC KEY");
                            System.out.println("CHECKING IF DIGEST/HASH IS VALID");

                            if (sessionKey != null) {
                                //DECRYPTING THE MESSAGE
                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                                byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

                                int messageLength = decryptedMessage.length - digestLength;
                                byte[] receivedM = new byte[messageLength];
                                byte[] receivedDigest = new byte[digestLength];
                                System.arraycopy(decryptedMessage, 0, receivedM, 0, messageLength);
                                System.arraycopy(decryptedMessage, messageLength, receivedDigest, 0, digestLength);

                                // Decrypt digest with the sender's public key
                                Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                decryptCipher.init(Cipher.DECRYPT_MODE, finalAlicePub);
                                byte[] decryptedDigest = decryptCipher.doFinal(receivedDigest);

                                MessageDigest md = MessageDigest.getInstance("SHA-256");
                                byte[] receivedMessageDigest = md.digest(receivedM);

                                boolean isDigestValid = MessageDigest.isEqual(receivedMessageDigest, decryptedDigest);

                                if (isDigestValid) {
                                    // Check if the received message is an image message
                                    String decryptedMessageString = new String(receivedM, "UTF-8");
                                    if (decryptedMessageString.startsWith("image:")) {
                                        // This is an image message
                                        StringBuilder imageDataBuilder = new StringBuilder();
                                        String[] parts = decryptedMessageString.split(",");
                                        if (parts.length == 3) {
                                            String base64ImageData = parts[0].substring("image:".length());
                                            String caption = parts[1];
                                            String extension =parts[2];

                                            // Decode and save the image
                                            byte[] imageData = Base64.getDecoder().decode(base64ImageData);
                                            String imagePath = "image."+ extension; // Specify the path to save the image
                                            Files.write(Paths.get(imagePath), imageData);

                                            // Display the caption
                                            System.out.println("Alice: " + caption);
                                        }
                                    } else {
                                        // This is a regular text message
                                        System.out.println("Alice: " + decryptedMessageString);
                                    }
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

                // Check so it doesn't send empty messages
                if (!message.isEmpty()) {
                    try {
                        byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                        if (sessionKey != null) {
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
                            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                            byte[] digest = md.digest(messageBytes);

                            // ENCRYPT DIGEST WITH PRIVATE KEY
                            System.out.println("ENCRYPTING DIGEST/HASH WITH BOB'S PRIVATE KEY");
                            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            rsaCipher.init(Cipher.ENCRYPT_MODE, bobPriv);
                            byte[] privEncryptedDigest = rsaCipher.doFinal(digest);
                            byte[] data = new byte[messageBytes.length + privEncryptedDigest.length];

                            System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                            System.arraycopy(privEncryptedDigest, 0, data, messageBytes.length, privEncryptedDigest.length);

                            // ENCRYPTING WHOLE MESSAGE WITH HASH/DIGEST
                            System.out.println("ENCRYPTING MESSAGE");
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                            byte[] encryptedMessage = cipher.doFinal(data);

                            // Encode the entire encryptedMessageBytes
                            System.out.println("ENCODING MESSAGE");
                            String Base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                            dataOutputStream.writeUTF(Base64EncryptedMessage);
                            System.out.println("SENDING MESSAGE");
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
    public static String decryptMessage(byte[] encryptedMessage, byte[] sessionKey, PrivateKey privateKey) {

    }
}

