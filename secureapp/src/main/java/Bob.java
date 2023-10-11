import keys.KeyUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

public class Bob {
    public static void main(String[] args) {
        PublicKey bobPub = null;
        PrivateKey bobPriv = null;
        PublicKey alicePub = null;
        try{

            bobPub = KeyUtils.readPublicKey("bob");
            bobPriv = KeyUtils.readPrivateKey("bob");
            alicePub = KeyUtils.readPublicKey("alice");
        }
        catch (Exception e){
            System.out.println(e);
        }

        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            //RECEIVE MESSAGES FROM ALICE
            PublicKey finalAlicePub = alicePub;
            Thread aliceListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();

                        // Decrypt with the recipient's public key
                        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        decryptCipher.init(Cipher.DECRYPT_MODE, finalAlicePub);
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
                            // Convert the delimiter string to bytes
                            byte[] delimiter = "#DELIMITER#".getBytes(StandardCharsets.UTF_8);

                            // Search for the delimiter in the received data
                            int delimiterIndex = indexOfByteArray(receivedM, delimiter);

                            byte[] receivedImageBytes = Arrays.copyOfRange(receivedM, 0, delimiterIndex);
                            byte[] receivedTextBytes = Arrays.copyOfRange(receivedM, delimiterIndex + delimiter.length, receivedM.length);

                            byte[] receivedCombinedDataDigest = md.digest(receivedM);
                            BufferedImage receivedImage = ImageIO.read(new ByteArrayInputStream(receivedImageBytes));
                            String receivedTextMessage = new String(receivedTextBytes, StandardCharsets.UTF_8);


                            File outputFile = new File("secureapp", "test.jpg");

                            // Write the BufferedImage to the file
                            ImageIO.write(receivedImage, "jpg", outputFile);

//                            String decryptedMessage = new String(receivedM, "UTF-8");

                            System.out.println("Alice: "+ receivedTextMessage);
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
            aliceListener.start();

            //SEND MESSAGES TO ALICE
            while (true) {
                String message = scanner.nextLine();
                //Checks so it doesnt send empty messages

                //1. Hash message - https://www.geeksforgeeks.org/sha-256-hash-in-java/

                // Static getInstance method is called with hashing SHA
                MessageDigest md = MessageDigest.getInstance("SHA-256");

                //Convert message to bytes
                byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);

                // digest() method called to calculate message digest of an input and return array of byte
                byte[] digest = md.digest(messageBytes);

                //join message and digest
                byte[] data = new byte[messageBytes.length + digest.length];

                System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                System.arraycopy(digest, 0, data, messageBytes.length, digest.length);

                //2. ENCRYPT HASHED MESSAGE WITH PRIVATE KEY
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, bobPriv);
                byte[] privEncryptedMessage = cipher.doFinal(data);//encrypts


                if (!message.isEmpty()) {
                    dataOutputStream.writeUTF(Base64.toBase64String(privEncryptedMessage));
                    System.out.println("sent:"+privEncryptedMessage.toString());
                }
                if (message.equalsIgnoreCase("exit")) {
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
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }


    public static int indexOfByteArray(byte[] source, byte[] target) {
        if (source == null || target == null || target.length == 0 || source.length < target.length) {
            return -1;
        }

        for (int i = 0; i <= source.length - target.length; i++) {
            boolean found = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }

        return -1; // Not found
    }
}