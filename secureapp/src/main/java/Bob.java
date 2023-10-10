import keys.KeyUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
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
            System.out.println(finalAlicePub);
            Thread aliceListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();

                        // Decrypt with the recipient's public key
                        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        decryptCipher.init(Cipher.DECRYPT_MODE, finalAlicePub);
                        byte[] decryptedBytes = decryptCipher.doFinal(Base64.decode(receivedMessage));
                        String decryptedMessage = new String(decryptedBytes, "UTF-8");

                        System.out.println("Alice: " + decryptedMessage);
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

                // digest() method called to calculate message digest of an input and return array of byte
                byte[] digest = md.digest(message.getBytes(StandardCharsets.UTF_8));

                //Convert message to bytes
                byte[] data = message.getBytes();

                //join message and digest

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
}
