import keys.KeyUtils;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.sql.SQLOutput;
import java.util.Scanner;

import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.io.FilenameUtils;

public class Alice {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePub = null;
        PrivateKey alicePriv = null;
        PublicKey bobPub = null;

        Scanner scanner = new Scanner(System.in);
        int port = 5001;
        AtomicReference<byte[]> sessionKeyRef = new AtomicReference<>();

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream.writeUTF("alice");

            //ALL KEYS
            alicePub = KeyUtils.readPublicKey("alice");
            alicePriv = KeyUtils.readPrivateKey("alice");
            bobPub = KeyUtils.readPublicKey("bob");

            boolean isFirstConnected = dataInputStream.readBoolean();
            System.out.println("FIRST TO CONNECT: "+ isFirstConnected);

            if (isFirstConnected) {
                System.out.println("CREATING SESSION KEY");

                // Initialize the RSA engine
                RSAKeyParameters rsaPublicKey = (RSAKeyParameters)PublicKeyFactory.createKey(bobPub.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(true, rsaPublicKey);

                // Generate a random session key.
                SecureRandom secureRandom = new SecureRandom();
                byte[] sessionKey = new byte[16];
                secureRandom.nextBytes(sessionKey);

                // Encrypt the session key with Bob's public key using RSA with PKCS1Padding
                System.out.println("ENCRYPTING SESSION KEY WITH BOB'S PUBLIC KEY");
                byte[] encryptedSessionKey = rsaEngine.processBlock(sessionKey, 0, sessionKey.length);

                // Encode the session key using base64
                System.out.println("ENCODING SESSION KEY");
                String base64SessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
                System.out.println("BASE64-ENCODED SESSION KEY: " + base64SessionKey);

                System.out.println("SENDING SESSION KEY TO BOB");
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
                RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(alicePriv.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(false, rsaPrivateKey);

                // Decrypt the encrypted session key
                System.out.println("DECRYPTING SESSION KEY WITH ALICE'S PRIVATE KEY");
                byte[] sessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);

                sessionKeyRef.set(sessionKey);
            }

            //RECEIVE MESSAGES FROM BOB
            PublicKey finalBobPub = bobPub;
            Thread bobListener = new Thread(() -> {
                try {
                    while (true) {
                        String base64EncryptedMessage = dataInputStream.readUTF();
                        int digestLength = 256; // For SHA-256


                        // Decode the Base64 string back into a byte array
                        System.out.println("DECODING MESSAGE");
                        byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);

                        try {
                            byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                            if (sessionKey != null) {
                                //DECRYPTING THE MESSAGE
                                System.out.println("DECRYPTING MESSAGE");
                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                                byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

                                int messageLength = decryptedMessage.length - digestLength;
                                byte[] receivedM = new byte[messageLength];
                                byte[] receivedDigest = new byte[digestLength];
                                System.arraycopy(decryptedMessage, 0, receivedM, 0, messageLength);
                                System.arraycopy(decryptedMessage, messageLength, receivedDigest, 0, digestLength);

                                // Decrypt digest with the sender's public key
                                System.out.println("DECRYPTING DIGEST/HASH WITH BOB'S PUBLIC KEY");
                                Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                decryptCipher.init(Cipher.DECRYPT_MODE, finalBobPub);
                                byte[] decryptedDigest = decryptCipher.doFinal(receivedDigest);

                                MessageDigest md = MessageDigest.getInstance("SHA-256");
                                byte[] receivedMessageDigest = md.digest(receivedM);

                                boolean isDigestValid = MessageDigest.isEqual(receivedMessageDigest, decryptedDigest);

                                System.out.println("CHECKING IF DIGEST/HASH IS VALID");
                                if (isDigestValid) {
                                    // Process the decrypted message as needed
                                    String decryptedMessageString = new String(receivedM, "UTF-8");
                                    System.out.println("Bob: " + decryptedMessageString);
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
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                String message = scanner.nextLine();

                //Checks so it doesn't send empty messages
                if (!message.isEmpty()) {
                    try {
                        byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session keyif (sessionKey != null) {
                        if (message.startsWith("image:")) {
                            // This is an image message
                            String[] parts = message.split(",", 2); // Split the message into image path and caption
                            String imagePath = parts[0].substring("image:".length()); // Extract the image path
                            String caption = parts[1]; // Extract the caption

                            // Load the image from the specified path
                            File imageFile = new File(imagePath);
                            if (imageFile.exists() && imageFile.isFile()) {
                                byte[] imageData = Files.readAllBytes(imageFile.toPath());

                                // Compress the image data
                                ByteArrayOutputStream compressedImageData = new ByteArrayOutputStream();
                                try (GZIPOutputStream gzipOutputStream = new GZIPOutputStream(compressedImageData)) {
                                    gzipOutputStream.write(imageData);
                                }

                                // Encode the compressed image data as Base64 and split it into chunks
                                byte[] compressedDataBytes = compressedImageData.toByteArray();
                                String compressedDataString = Base64.getEncoder().encodeToString(compressedDataBytes);
                                int chunkSize = 1024; // Define your preferred chunk size

                                for (int i = 0; i < compressedDataString.length(); i += chunkSize) {
                                    String chunk = compressedDataString.substring(i, Math.min(i + chunkSize, compressedDataString.length()));
                                    String messageChunk = "image:" + chunk;

                                    String encryptedMessage = encryptMessage(messageChunk, sessionKey, alicePriv);
                                    dataOutputStream.writeUTF(encryptedMessage);
                                }
                                System.out.println("SENDING IMAGE CHUNKS");
                               // Send the caption and extension at the end
                                String captionAndExtension = caption + "," + FilenameUtils.getExtension(imagePath);
                                dataOutputStream.writeUTF(captionAndExtension);
                                System.out.println("SENDING CAPTION AND EXTENSION");
                            } else {
                                System.out.println("ERROR: Image file not found: " + imagePath);
                            }

                            } else {
                            String encryptedMessage = encryptMessage(message, sessionKey, alicePriv);
                            dataOutputStream.writeUTF(encryptedMessage);
                            System.out.println("ENCRYPTING DIGEST/HASH WITH ALICE'S PRIVATE KEY");
                            System.out.println("ENCRYPTING MESSAGE");
                            System.out.println("ENCODING MESSAGE");
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
    public static String encryptMessage(String message, byte[] sessionKey, PrivateKey privateKey) throws Exception {
        //HASH
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] digest = md.digest(messageBytes);

        // ENCRYPT DIGEST WITH PRIVATE KEY
        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] privEncryptedDigest = rsaCipher.doFinal(digest);
        byte[] data = new byte[messageBytes.length + privEncryptedDigest.length];

        System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
        System.arraycopy(privEncryptedDigest, 0, data, messageBytes.length, privEncryptedDigest.length);

        // ENCRYPTING WHOLE MESSAGE WITH HASH/DIGEST
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
        byte[] encryptedMessage = cipher.doFinal(data);

        // Encode the entire encryptedMessageBytes
        String Base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);

        return Base64EncryptedMessage;
    }

}