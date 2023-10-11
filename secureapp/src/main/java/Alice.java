import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import keys.KeyUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileReader;
import java.util.jar.JarException;

public class Alice {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePub = null;
        PrivateKey alicePriv = null;
        PublicKey bobPub = null;
        try{

            alicePub = KeyUtils.readPublicKey("alice");
            alicePriv = KeyUtils.readPrivateKey("alice");
            bobPub = KeyUtils.readPublicKey("bob");
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
                String message = scanner.nextLine();
                //Checks so it doesnt send empty messages

                //1. Hash message - https://www.geeksforgeeks.org/sha-256-hash-in-java/

                // Static getInstance method is called with hashing SHA
                MessageDigest md = MessageDigest.getInstance("SHA-256");

                //Convert message to bytes
                byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                // digest() method called to calculate message digest of an input and return array of byte
                byte[] digest = md.digest(messageBytes);

                byte[] data = new byte[messageBytes.length + digest.length];

                System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                System.arraycopy(digest, 0, data, messageBytes.length, digest.length);

                //join message and digest
//                byte[] data = messageBytes+digest;

                //2. ENCRYPT HASHED MESSAGE WITH PRIVATE KEY
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, alicePriv);
                byte[] privEncryptedMessage = cipher.doFinal(data);//encrypts

                //

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
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}