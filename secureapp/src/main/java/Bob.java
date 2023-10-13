import keys.KeyUtils;

import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jcajce.provider.asymmetric.X509;
import org.bouncycastle.jcajce.provider.symmetric.ARC4.Base;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.SQLOutput;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPInputStream;
import java.util.zip.Inflater;

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
        PublicKey alicePublicKey = null;
        PublicKey caPublicKey = null;
        X509Certificate bobCert = null;

        Scanner scanner = new Scanner(System.in);
        int port = 5001;
        AtomicReference<byte[]> sessionKeyRef = new AtomicReference<>();

        try{
            FileInputStream fileInp = new FileInputStream(bobKeyStorePath);
            KeyStore bobKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            bobKeyStore.load(fileInp, bobKeyStorePassword.toCharArray());
            bobCert =  (X509Certificate) bobKeyStore.getCertificate(bobAlias);
            bobPublicKey = bobCert.getPublicKey();
            bobPrivateKey = (PrivateKey) bobKeyStore.getKey(bobAlias,bobKeyStorePassword.toCharArray());
            // System.out.println("BOB CERT "+ bobCert.toString());

            FileInputStream caFileInput = new FileInputStream(caCertPath);
            KeyStore caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            caKeyStore.load(caFileInput, caPassword.toCharArray());
            caPublicKey = ((X509Certificate) caKeyStore.getCertificate(caAlias)).getPublicKey();
            // System.out.println("CA" + caPublicKey.toString());
            
            //Alice's public key
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new FileInputStream("secureapp/src/main/java/config/alice.cer"));
            alicePublicKey = cert.getPublicKey();
            
            // System.out.println("BOB: " + alicePublicKey);
            System.out.println("Bob's certificate, public key and CA public key loaded");
        }
        catch (Exception e){
            System.out.println(e);
        }
        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            dataOutputStream.writeUTF("bob");

            boolean isFirstConnected = dataInputStream.readBoolean();
            System.out.println("First to connect: "+ isFirstConnected);
            boolean verified = false;
            
            // get Alice's Certificate
            String encCert = dataInputStream.readUTF();
            
            byte [] certBytes = Base64.getDecoder().decode((encCert.replace("[", "")).replace("]", ""));
            CertificateFactory alCertificateFactory = CertificateFactory.getInstance("X.509") ;
            X509Certificate aliceCert = (X509Certificate) alCertificateFactory.generateCertificate(new ByteArrayInputStream(certBytes));
            // System.out.println("HERE " + aliceCert.toString());

            //Send certificate to Alice
            String base64BobCert = Base64.getEncoder().encodeToString(bobCert.getEncoded());
            dataOutputStream.writeUTF(base64BobCert);

            try {
                aliceCert.verify(caPublicKey);
                verified = true;
                System.out.println("Verified Alice's certificate");

                if (isFirstConnected) {
                    System.out.println("CREATING SECRET KEY");

                    // Initialize the RSA engine
                    RSAKeyParameters rsaPublicKey = (RSAKeyParameters) PublicKeyFactory.createKey(alicePublicKey.getEncoded());
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
                        RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPrivateKey.getEncoded());
                        RSAEngine rsaEngine = new RSAEngine();
                        rsaEngine.init(false, rsaPrivateKey);

                    // Decrypt the encrypted session key
                    byte[] sessionKey = rsaEngine.processBlock(encryptedSessionKey, 0, encryptedSessionKey.length);
                    System.out.println("DECRYPTED key " + Arrays.toString(sessionKey));

                    sessionKeyRef.set(sessionKey);

                }

                //RECEIVE MESSAGES FROM ALICE
                Thread aliceListener = new Thread(() -> {
                    try {
                        while (true) {

                            String base64EncryptedMessage = dataInputStream.readUTF();

                            // Decode the Base64 string back into a byte array
                            byte[] encryptedMessage = Base64.getDecoder().decode(base64EncryptedMessage);

                        try {
                            byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key

                            if (sessionKey != null) {
                                int messageLength = encryptedMessage.length - digestLength;
                                byte[] receivedM = new byte[messageLength];
                                byte[] receivedDigest = new byte[digestLength];
                                System.arraycopy(encryptedMessage, 0, receivedM, 0, messageLength);
                                System.arraycopy(encryptedMessage, messageLength, receivedDigest, 0, digestLength);

                                System.out.println("Decrypting message.");
                                Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as used for encryption
                                cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                                byte[] decryptedMessage = cipher.doFinal(receivedM);

                                System.out.println("Decrypting digest.");
                                // Decrypt digest with the sender's public key
                                Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                                decryptCipher.init(Cipher.DECRYPT_MODE, finalAlicePub);
                                byte[] decryptedDigest = decryptCipher.doFinal(receivedDigest);

                                System.out.println("Creating digest.");
                                MessageDigest md = MessageDigest.getInstance("SHA-1");
                                byte[] receivedMessageDigest = md.digest(decryptedMessage);

                                boolean isDigestValid = MessageDigest.isEqual(receivedMessageDigest, decryptedDigest);

                                if (isDigestValid) {
                                    System.out.println("Digest Valid.");
                                    String stringM =new String(decryptedMessage, StandardCharsets.UTF_8);

                                    String[] lines = stringM.split(" DELIMITER ");

                                    System.out.println("Decrypted message: " + lines[1]);
                                    saveDecodedDataToDesktop(lines[0], lines[1]);
                                    System.out.println("Image saved.");
                                    System.out.println("Please enter the file path: ");
                                }
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
            aliceListener.start();

            //SEND MESSAGES TO ALICE
            while (true) {
                System.out.println("Please enter the file path: ");
                String filePath = scanner.nextLine();

                System.out.println("Please enter the caption: ");
                String caption = scanner.nextLine(); // Read user input
                System.out.println("File path is: " + filePath); // Output user input

                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(caption + " with image " + filePath);

                //Checks so it doesn't send empty messages
                if (!caption.isEmpty() && !filePath.isEmpty()) {
                    try {
                        byte[] sessionKey = sessionKeyRef.get(); // Retrieve the session key
                        if (sessionKey != null) {
                            System.out.println("Reading and encoding image and caption.");
                            File imageFile = new File(filePath);
                            FileInputStream fis = new FileInputStream(imageFile); // input stream

                            BufferedImage img = ImageIO.read(imageFile);
                            BufferedImage image = org.imgscalr.Scalr.resize(img, 500);
                            // Read and encode the image as Base64

                            ByteArrayOutputStream baos = new ByteArrayOutputStream();
                            ImageIO.write(image, "jpg", baos);

                            byte[] imageBytes = baos.toByteArray();

                            String base64Image = Base64.getEncoder().encodeToString((imageBytes));
                            String stringMessage = base64Image+" DELIMITER "+caption;

                            System.out.println("Creating digest");
                            MessageDigest md = MessageDigest.getInstance("SHA-1");
                            byte[] digest = md.digest(stringMessage.getBytes(StandardCharsets.UTF_8));

                            //2. ENCRYPT DIGEST WITH PRIVATE KEY
                            System.out.println("Encrypting digest");
                            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            rsaCipher.init(Cipher.ENCRYPT_MODE, bobPriv);
                            byte[] privEncryptedDigest = rsaCipher.doFinal(digest);

                            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same algorithm and mode as on the other end
                            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(sessionKey, "AES"));
                            byte[] encryptedMessage = cipher.doFinal(stringMessage.getBytes(StandardCharsets.UTF_8));

                            System.out.println("Bundling digest and message.");
                            byte[] data = new byte[encryptedMessage.length + privEncryptedDigest.length];
                            System.arraycopy(encryptedMessage, 0, data, 0, encryptedMessage.length);
                            System.arraycopy(privEncryptedDigest, 0, data, encryptedMessage.length, privEncryptedDigest.length);

                            System.out.println("Sending message");
                            String Base64EncryptedMessage = Base64.getEncoder().encodeToString(data);
                            dataOutputStream.writeUTF(Base64EncryptedMessage);
                        }
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                    if (caption.equalsIgnoreCase("exit")) {
                        break;
                    }
                } else {
                    System.out.println("something is empty");
                }
            }
            socket.close();
        }  catch (Exception e) {
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
    public static boolean saveDecodedDataToDesktop(String base64Image, String fileName) {
        try {
            // Decode the Base64 image data
            byte[] decodedImageBytes = Base64.getDecoder().decode(base64Image);

            // Create a BufferedImage from the decoded byte array
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedImageBytes);
            BufferedImage image = ImageIO.read(bais);
            String outputFile = fileName +".jpg";

            // Save the decrypted image to the specified output path
            ImageIO.write(image, "jpg", new File(outputFile));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false; // Data save operation failed
    }
}

