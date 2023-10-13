import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.*;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class Bob {
    private static final String bobKeyStorePath = "secureapp/src/main/java/config/KeyStoreBob";
    private static final String bobKeyStorePassword = "123456";
    private static final String bobAlias = "bob-alias";

    private static final String caCertPath = "secureapp/src/main/java/config/KeyStoreCA";
    private static final String caPassword = "123456";
    private static final String caAlias = "ca";
    public static void main(String[] args) {
        PublicKey bobPublicKey = null;
        PrivateKey bobPrivateKey = null;
        PublicKey alicePub = null;
        PublicKey caPublicKey = null;
        X509Certificate bobCert = null;


        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try{
            FileInputStream fileInp = new FileInputStream(bobKeyStorePath);
            KeyStore bobKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            bobKeyStore.load(fileInp, bobKeyStorePassword.toCharArray());
            bobCert =  (X509Certificate) bobKeyStore.getCertificate(bobAlias);
            bobPublicKey = bobCert.getPublicKey();
            bobPrivateKey = (PrivateKey) bobKeyStore.getKey(bobAlias,bobKeyStorePassword.toCharArray());
            // System.out.println(bobCert.toString());
            FileInputStream caFileInput = new FileInputStream(caCertPath);
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(caFileInput, caPassword.toCharArray());
            caPublicKey = ((X509Certificate) caKeyStore.getCertificate(caAlias)).getPublicKey();
            // System.out.println("CA" + caPublicKey.toString());
            System.out.println("Bob's certificate, public key and CA public key loaded");
        }
        catch (Exception e){
            System.out.println(e);
        }


        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF("bob");

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

//          // Read the base64-encoded session key as a string
            String base64EncryptedSessionKey = dataInputStream.readUTF();

            // Decode the Base64 string back into a byte array
            byte[] encryptedSessionKey = Base64.getDecoder().decode(base64EncryptedSessionKey);

            // Initialize the RSA engine with Bob's private key
            RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPrivateKey.getEncoded());
            RSAEngine rsaEngine = new RSAEngine();
            rsaEngine.init(false, rsaPrivateKey);

            // Decrypt the encrypted session key
            byte[] decryptedSessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
            // System.out.println("DECRYPTED key "+ Arrays.toString(decryptedSessionKey));

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
        } catch (IOException e) {
            e.printStackTrace();
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}