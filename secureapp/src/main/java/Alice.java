import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

//import java.io.*;
//import java.net.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
//import org.bouncycastle.crypto.paddings.PKCS5Padding;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Alice {
    private static final String aliceKeyStorePath = "secureapp/src/main/java/config/KeyStoreAlice";
    private static final String aliceKeyStorePassword = "123456";
    private static final String aliceAlias = "alice-alias";

    private static final String caCertPath = "secureapp/src/main/java/config/KeyStoreCA";
    private static final String caPassword = "123456";
    private static final String caAlias = "ca";

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePublicKey = null;
        PrivateKey alicePrivateKey = null;
        PublicKey bobPublicKey = null;
        PublicKey caPublicKey = null;

        X509Certificate caCert= null;
        X509Certificate aliceCert = null;

        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try{
            //Loading in Alice's certificate and keys
            FileInputStream aliceFileInp = new FileInputStream(aliceKeyStorePath);
            KeyStore aliceKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            aliceKeyStore.load(aliceFileInp, aliceKeyStorePassword.toCharArray());
            aliceCert =  (X509Certificate) aliceKeyStore.getCertificate(aliceAlias);
            alicePublicKey = aliceCert.getPublicKey();
            alicePrivateKey = (PrivateKey) aliceKeyStore.getKey(aliceAlias, aliceKeyStorePassword.toCharArray());
            // System.out.println(aliceCert.toString());
            
            //loading in CA's public key
            FileInputStream caFileInput = new FileInputStream(caCertPath);
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(caFileInput, caPassword.toCharArray());
            caCert = (X509Certificate) caKeyStore.getCertificate(caAlias);
            // System.out.println("CA: " + caCert.toString());
            caPublicKey = caCert.getPublicKey();
            
            //loading in Bob's pubblic key
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new FileInputStream("secureapp/src/main/java/config/bob.cer"));
            bobPublicKey = cert.getPublicKey();

            // System.out.println("BOB: " + bobPublicKey);
            System.out.println("Alice's certificate, public key and CA public key loaded");

        }
        catch (Exception e){
            System.out.println(e);
        }
        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            dataOutputStream.writeUTF("alice");

            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());


            // Initialize the RSA engine
            RSAKeyParameters rsaPublicKey = (RSAKeyParameters)PublicKeyFactory.createKey(bobPublicKey.getEncoded());
            RSAEngine rsaEngine = new RSAEngine();
            rsaEngine.init(true, rsaPublicKey);

            // Generate a random session key.
            SecureRandom secureRandom = new SecureRandom();
            byte[] sessionKey = new byte[16];
            secureRandom.nextBytes(sessionKey);
            // System.out.println("sessionkey: "+ Arrays.toString(sessionKey));

            // Encrypt the session key with Bob's public key using RSA with PKCS1Padding
            byte[] encryptedSessionKey = rsaEngine.processBlock(sessionKey, 0, sessionKey.length);

            // Encode the session key using base64
            String base64SessionKey = Base64.getEncoder().encodeToString(encryptedSessionKey);
            // System.out.println("Base64-encoded Session Key: " + base64SessionKey);

            // Decrypt the encrypted session key
            byte[] decryptedSessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
            // System.out.println("DECRYPTED key "+ Arrays.toString(decryptedSessionKey));

            dataOutputStream.writeUTF(base64SessionKey);
//
            //RECEIVE MESSAGES FROM BOB
            PublicKey finalBobPub = bobPublicKey;
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
                                // System.out.println("Decrypted message: " + decryptedMessageString);
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
                        rsaCipher.init(Cipher.ENCRYPT_MODE, alicePrivateKey);
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