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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Bob {
    public static void main(String[] args) {
        PublicKey bobPub;
        PrivateKey bobPriv;
        PublicKey alicePub;


        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF("bob");

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

//            bobPub = KeyUtils.readPublicKey("bob");
            bobPriv = KeyUtils.readPrivateKey("bob");
//            alicePub = KeyUtils.readPublicKey("alice");

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
            Thread aliceListener = new Thread(() -> {
                try {
                    while (true) {

                         String base64EncryptedMessage = dataInputStream.readUTF();

                        // Decode the Base64 string back into a byte array
                        byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);

                        try {
                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(decryptedSessionKey, "AES"));

                            byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

                            // Process the decrypted message as needed
                            String decryptedMessageString = new String(decryptedMessage, "UTF-8");
                            System.out.println("Decrypted message: " + decryptedMessageString);

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
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}

