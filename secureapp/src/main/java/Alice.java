import keys.KeyUtils;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
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
import java.util.zip.Deflater;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

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
            System.out.println("First to connect: "+ isFirstConnected);

            if (isFirstConnected) {
                System.out.println("CREATING SECRET KEY");

                // Initialize the RSA engine
                RSAKeyParameters rsaPublicKey = (RSAKeyParameters)PublicKeyFactory.createKey(bobPub.getEncoded());
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
                RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(alicePriv.getEncoded());
                RSAEngine rsaEngine = new RSAEngine();
                rsaEngine.init(false, rsaPrivateKey);

                // Decrypt the encrypted session key
                byte[] sessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
                System.out.println("DECRYPTED key "+ Arrays.toString(sessionKey));

                sessionKeyRef.set(sessionKey);
            }
//            System.out.println(isFirstConnected);


            //RECEIVE MESSAGES FROM BOB
            PublicKey finalBobPub = bobPub;
            Thread bobListener = new Thread(() -> {
                try {
                    while (true) {
                        String base64EncryptedMessage = dataInputStream.readUTF();
                        int digestLength = 256; // For SHA-256
                        // Decode the Base64 string back into a byte array
                        byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);

                        try {
                            byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                            if (sessionKey != null) {
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
                                decryptCipher.init(Cipher.DECRYPT_MODE, finalBobPub);
                                byte[] decryptedDigest = decryptCipher.doFinal(receivedDigest);

                                MessageDigest md = MessageDigest.getInstance("SHA-256");
                                byte[] receivedMessageDigest = md.digest(receivedM);

                                boolean isDigestValid = MessageDigest.isEqual(receivedMessageDigest, decryptedDigest);

                                if (isDigestValid) {
                                    // Process the decrypted message as needed
                                    String decryptedMessageString = new String(receivedM, "UTF-8");
                                    System.out.println("Decrypted message: " + decryptedMessageString);
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
                System.out.println("Please enter the file path: ");
                String filePath = scanner.nextLine();

                System.out.println("Please enter the caption: ");
                String caption = scanner.nextLine(); // Read user input
                System.out.println("File path is: " + filePath); // Output user input

                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(caption +" with image "+ filePath);

                //Checks so it doesn't send empty messages
                if (!caption.isEmpty() && !filePath.isEmpty()) {
                    try {
                        System.out.println("try");
                        byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key
                        if (sessionKey != null) {
                            System.out.println("try");
                            File imageFile = new File(filePath);
                            FileInputStream fis = new FileInputStream(imageFile); // input stream

                            // Read and encode the image as Base64
                            byte[] buffer = new byte[1024];
                            int bytesRead; //tracks the number of bytes read in each iteration.
                            ByteArrayOutputStream baos = new ByteArrayOutputStream();

                            //This loop reads the image data from an input stream,(fis),and stores it in a buffer.
                            //It reads the image data in chunks of buffer.length bytes at a time until it reaches the
                            //end of the input stream.
                            while ((bytesRead = fis.read(buffer)) != -1) {
                                baos.write(buffer, 0, bytesRead);
                            }

                            byte[] imageBytes = baos.toByteArray();
                            String base64Image = Base64.getEncoder().encodeToString(imageBytes);
                            byte[] byteEncodedImage = base64Image.getBytes(StandardCharsets.UTF_8);
                            byte[] byteCaption = caption.getBytes(StandardCharsets.UTF_8);

                            byte[] delimiter = new byte[] { 0x00 }; // Null byte as delimiter

                            byte[] messageBytes = new byte[byteEncodedImage.length + 1 + byteCaption.length];
                            System.arraycopy(byteEncodedImage, 0, messageBytes, 0, byteEncodedImage.length);
                            System.arraycopy(delimiter, 0, messageBytes, byteEncodedImage.length, 1);
                            System.arraycopy(byteCaption, 0, messageBytes, byteEncodedImage.length + 1, byteCaption.length);

//                            byte[] messageBytes = compressData(unCompressedMessageBytes);
                            System.out.println("compressed");
                            MessageDigest md = MessageDigest.getInstance("SHA-256");
//                            byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                            byte[] digest = md.digest(messageBytes);

                            //2. ENCRYPT DIGEST WITH PRIVATE KEY
                            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            rsaCipher.init(Cipher.ENCRYPT_MODE, alicePriv);
                            byte[] privEncryptedDigest = rsaCipher.doFinal(digest);
                            byte[] data = new byte[messageBytes.length + privEncryptedDigest.length];

                            System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                            System.arraycopy(privEncryptedDigest, 0, data, messageBytes.length, privEncryptedDigest.length);
                            System.out.println("shout");
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                            byte[] encryptedMessage = cipher.doFinal(data);
                            System.out.println(encryptedMessage.toString());

                            // Encode the entire encryptedMessageBytes
                            String Base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                            dataOutputStream.writeUTF(Base64EncryptedMessage);
                            System.out.println("out");
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    if (caption.equalsIgnoreCase("exit")) {
                        break;
                    }
                } else {
                    System.out.println("something is empty");
                }
            }
            socket.close();
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }

//    public static byte[] compressData(byte[] data) {
//        try {
//            System.out.println("compression");
//            ByteArrayOutputStream compressedStream = new ByteArrayOutputStream();
//            Deflater deflater = new Deflater();
//            deflater.setInput(data);
//
//            byte[] buffer = new byte[1024]; // Use a suitable buffer size
//            while (!deflater.finished()) {
//                int compressedSize = deflater.deflate(buffer);
//                compressedStream.write(buffer, 0, compressedSize);
//            }
//
//            deflater.end();
//            compressedStream.close();
//
//            return compressedStream.toByteArray();
//        } catch (Exception e) {
//            e.printStackTrace();
//            return null;
//        }
//    }
}
