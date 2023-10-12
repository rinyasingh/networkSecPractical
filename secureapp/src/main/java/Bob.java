import keys.KeyUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Bob {
    public static void main(String[] args) {
        PublicKey bobPub;
        PrivateKey bobPriv;
        PublicKey alicePub = null;


        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF("bob");

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

//            bobPub = KeyUtils.readPublicKey("bob");
            bobPriv = KeyUtils.readPrivateKey("bob");
            alicePub = KeyUtils.readPublicKey("alice");

//          // Read the base64-encoded session key as a string
            String base64EncryptedSessionKey = dataInputStream.readUTF();

            // Decode the Base64 string back into a byte array
            byte[] encryptedSessionKey = Base64.getDecoder().decode(base64EncryptedSessionKey);

            // Initialize the RSA engine with Bob's private key
            RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPriv.getEncoded());
            RSAEngine rsaEngine = new RSAEngine();
            rsaEngine.init(false, rsaPrivateKey);

            // Decrypt the encrypted session key
            byte[] decryptedSessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
            System.out.println("DECRYPTED key "+ Arrays.toString(decryptedSessionKey));

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
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedSessionKey, "AES"));
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
                                // Process the decrypted message as needed
                                String decryptedMessageString = new String(receivedM, "UTF-8");
                                System.out.println("Decrypted message: " + decryptedMessageString);
                            } else {
                                System.out.println("Message Digest is NOT Valid");
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

                        byte[] messageBytes = message.getBytes();
                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(decryptedSessionKey, "AES"));
                        byte[] encryptedMessage = cipher.doFinal(messageBytes);

                        // Encode the entire encryptedMessageBytes
                        String Base64EncryptedMessage = Base64.getEncoder().encodeToString(encryptedMessage);
                        dataOutputStream.writeUTF(Base64EncryptedMessage);


                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    if (message.equalsIgnoreCase("exit")) {
                        break;
                    }
                }
            }
            socket.close();
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}