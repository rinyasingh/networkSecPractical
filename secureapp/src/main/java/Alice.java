import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
        AtomicReference<byte[]> sessionKeyRef = new AtomicReference<>();
        try{
            //Loading in Alice's certificate and keys
            FileInputStream aliceFileInp = new FileInputStream(aliceKeyStorePath);
            KeyStore aliceKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            aliceKeyStore.load(aliceFileInp, aliceKeyStorePassword.toCharArray());
            aliceCert =  (X509Certificate) aliceKeyStore.getCertificate(aliceAlias);
            alicePublicKey = aliceCert.getPublicKey();
            alicePrivateKey = (PrivateKey) aliceKeyStore.getKey(aliceAlias, aliceKeyStorePassword.toCharArray());
            // System.out.println("ALICE CERT :"+aliceCert.toString());
            
            //loading in CA's public key
            FileInputStream caFileInput = new FileInputStream(caCertPath);
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(caFileInput, caPassword.toCharArray());
            caCert = (X509Certificate) caKeyStore.getCertificate(caAlias);
            // System.out.println("CA: " + caCert.toString());
            caPublicKey = caCert.getPublicKey();
            
            //loading in Bob's public key
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
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream.writeUTF("alice");

            boolean isFirstConnected = dataInputStream.readBoolean();
            System.out.println("First to connect: "+ isFirstConnected);

            boolean verified = false;
            //send certificate to Bob
            String base64AliceCert = Base64.getEncoder().encodeToString(aliceCert.getEncoded());
            dataOutputStream.writeUTF(base64AliceCert);
            // System.out.println(aliceCert.toString());

            // get Bob's Certificate
            String encCert = dataInputStream.readUTF();
            System.out.println(encCert);
            byte [] certBytes = Base64.getDecoder().decode((encCert.replace("[", "")).replace("]", ""));
            CertificateFactory bobCertificateFactory = CertificateFactory.getInstance("X.509") ;
            X509Certificate bobCert = (X509Certificate) bobCertificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
            System.out.println("HERE " + aliceCert.toString());

            try {
                bobCert.verify(caPublicKey);
                verified= true;
                System.out.print("Verified Bob's certificate");

                if (isFirstConnected) {
                    
                    System.out.println("CREATING SECRET KEY");

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
                    RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(alicePrivateKey.getEncoded());
                    RSAEngine rsaEngine = new RSAEngine();
                    rsaEngine.init(false, rsaPrivateKey);

                    // Decrypt the encrypted session key
                    byte[] sessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
                    // System.out.println("DECRYPTED key "+ Arrays.toString(sessionKey));

                    sessionKeyRef.set(sessionKey);
                }

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
                    // System.out.println(message);

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
                System.err.println("VERIFICATION FAILED");
            }
        } catch (Exception e) {
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}
