import keys.KeyUtils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
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
            Thread bobListener = new Thread(() -> {
                try {
                    while (true) {
                        String base64EncryptedMessage = dataInputStream.readUTF();

                        // Decode the Base64 string back into a byte array
                        byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);

                        try {
                            byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                            if (sessionKey != null) {
                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));

                                byte[] decryptedMessage = cipher.doFinal(encryptedMessage);

                                // Process the decrypted message as needed
                                String decryptedMessageString = new String(decryptedMessage, "UTF-8");
                                System.out.println("Decrypted message: " + decryptedMessageString);
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
                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(message);

                //Checks so it doesn't send empty messages
                if (!message.isEmpty()) {
                    try {
                        byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key
                        if (sessionKey != null) {
                        byte[] messageBytes = message.getBytes();
                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                        byte[] encryptedMessage = cipher.doFinal(messageBytes);

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
}