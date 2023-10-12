import keys.KeyUtils;
import org.bouncycastle.crypto.InvalidCipherTextException;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

//import java.io.*;
//import java.net.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import keys.KeyUtils;

import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.BlockCipherPadding;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
//import org.bouncycastle.crypto.paddings.PKCS5Padding;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;

public class Alice {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePub = null;
        PrivateKey alicePriv = null;
        PublicKey bobPub = null;

        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF("alice");

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

            //ALL KEYS
            alicePub = KeyUtils.readPublicKey("alice");
            alicePriv = KeyUtils.readPrivateKey("alice");
            bobPub = KeyUtils.readPublicKey("bob");

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

            // Decrypt the encrypted session key
            byte[] decryptedSessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
            System.out.println("DECRYPTED key "+ Arrays.toString(decryptedSessionKey));

            dataOutputStream.writeUTF(base64SessionKey);
//
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
                            decryptCipher.init(Cipher.DECRYPT_MODE, finalBobPub);
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
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                String message = scanner.nextLine();
                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(message);

                //Checks so it doesn't send empty messages
                if (!message.isEmpty()) {
                    try {
                        MessageDigest md = MessageDigest.getInstance("SHA-256");
                        byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
                        byte[] digest = md.digest(messageBytes);

                        //2. ENCRYPT DIGEST WITH PRIVATE KEY
                        Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        rsaCipher.init(Cipher.ENCRYPT_MODE, alicePriv);
                        byte[] privEncryptedDigest = rsaCipher.doFinal(digest);
                        byte[] data = new byte[messageBytes.length + privEncryptedDigest.length];

                        System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                        System.arraycopy(privEncryptedDigest, 0, data, messageBytes.length, privEncryptedDigest.length);

//                        byte[] messageBytes = message.getBytes();

                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                        byte[] encryptedMessage = cipher.doFinal(data);

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
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}