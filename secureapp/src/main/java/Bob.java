import keys.KeyUtils;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;
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
            Thread aliceListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();

                        // Decrypt with the recipient's public key
                        Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                        decryptCipher.init(Cipher.DECRYPT_MODE, finalAlicePub);
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
                            // Convert the delimiter string to bytes
                            byte[] delimiter = "#DELIMITER#".getBytes(StandardCharsets.UTF_8);

                            // Search for the delimiter in the received data
                            int delimiterIndex = indexOfByteArray(receivedM, delimiter);

                            byte[] receivedImageBytes = Arrays.copyOfRange(receivedM, 0, delimiterIndex);
                            byte[] receivedTextBytes = Arrays.copyOfRange(receivedM, delimiterIndex + delimiter.length, receivedM.length);

                            byte[] receivedCombinedDataDigest = md.digest(receivedM);
                            BufferedImage receivedImage = ImageIO.read(new ByteArrayInputStream(receivedImageBytes));
                            String receivedTextMessage = new String(receivedTextBytes, StandardCharsets.UTF_8);


                            File outputFile = new File("secureapp", "test.jpg");

                            // Write the BufferedImage to the file
                            ImageIO.write(receivedImage, "jpg", outputFile);

//                            String decryptedMessage = new String(receivedM, "UTF-8");

                            System.out.println("Alice: "+ receivedTextMessage);
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
            aliceListener.start();

            //SEND MESSAGES TO ALICE
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

                //join message and digest
                byte[] data = new byte[messageBytes.length + digest.length];

                System.arraycopy(messageBytes, 0, data, 0, messageBytes.length);
                System.arraycopy(digest, 0, data, messageBytes.length, digest.length);

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


    public static int indexOfByteArray(byte[] source, byte[] target) {
        if (source == null || target == null || target.length == 0 || source.length < target.length) {
            return -1;
        }

        for (int i = 0; i <= source.length - target.length; i++) {
            boolean found = true;
            for (int j = 0; j < target.length; j++) {
                if (source[i + j] != target[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return i;
            }
        }

        return -1; // Not found
    }
}
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

            int readbytes = 0;

            int keyLength = dataInputStream.readInt();
            System.out.println("INT RECEIVED "+ keyLength);
            readbytes = keyLength;

            byte [] sessionKey = dataInputStream.readNBytes(readbytes);
            System.out.println("BYTES RECEIVED "+ Arrays.toString(sessionKey));

            // Initialize the RSA engine with Bob's private key
            RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPriv.getEncoded());
            RSAEngine rsaEngine = new RSAEngine();
            rsaEngine.init(false, rsaPrivateKey);

            // Decrypt the encrypted session key
            byte[] decryptedSessionKey = rsaEngine.processBlock(sessionKey, 0, keyLength);
            System.out.println("DECRYPTED key "+ Arrays.toString(decryptedSessionKey));

            //RECEIVE MESSAGES FROM ALICE
            Thread aliceListener = new Thread(() -> {
                try {
                    while (true) {

                        int bytesToRead1 = 0;
                        int bytesToRead2 = 0;

                        String input =  dataInputStream.readUTF();
                        System.out.println("UTF RECEIVED "+ input);
                        int msgLengthWithoutPadding = dataInputStream.readInt();
                        System.out.println("msg length: "+msgLengthWithoutPadding);
                        int ivBytelength = dataInputStream.readInt();
                        bytesToRead1 = ivBytelength;
                        System.out.println("INT RECEIVED "+ ivBytelength);

                        byte [] ivBytes = dataInputStream.readNBytes(bytesToRead1);
                        System.out.println("BYTES RECEIVED "+ Arrays.toString(ivBytes));

                        int encryptedMsgByteslength = dataInputStream.readInt();
                        System.out.println("INT RECEIVED "+ encryptedMsgByteslength);

                        bytesToRead2 = encryptedMsgByteslength;
                        byte [] encryptedMsgBytes = dataInputStream.readNBytes(bytesToRead2);

                        System.out.println("BYTES RECEIVED "+ Arrays.toString(encryptedMsgBytes));

                        try {
                            //decrypting message with session key
                            KeyParameter keyParam = new KeyParameter(decryptedSessionKey);
                            BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
                            CipherParameters params = new ParametersWithIV(keyParam, ivBytes);
                            cipher.init(false, params); // Set to false for decryption
                            byte[] decryptedMsgBytes = new byte[cipher.getOutputSize(encryptedMsgBytes.length)];

                            int bytesWritten = cipher.processBytes(encryptedMsgBytes, 0, encryptedMsgByteslength, decryptedMsgBytes, 0);
                            bytesWritten += cipher.doFinal(decryptedMsgBytes, bytesWritten);

                            // Trim the decryptedMessageBytes to the actual size
                            byte[] trimmedDecryptedMsgBytes = Arrays.copyOf(decryptedMsgBytes, msgLengthWithoutPadding);

                            // Convert the decrypted message bytes to a string
                            String decryptedMessage = new String(trimmedDecryptedMsgBytes, StandardCharsets.UTF_8);
                            System.out.println("Decrypted message: " + decryptedMessage);

                        }
                        catch (InvalidCipherTextException e) {
                            throw new RuntimeException(e);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            aliceListener.start();

            //SEND MESSAGES TO ALICE
            while (true) {
                String message = scanner.nextLine();
                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(message);

                dataOutputStream.writeUTF(PayloadTypes.UTF.getDataType());
                dataOutputStream.flush();

                dataOutputStream.writeUTF(message);
                dataOutputStream.flush();

                // Check so it doesn't send empty messages
                if (!message.isEmpty()) {
//                    dataOutputStream.writeUTF(message);

                    try {
                        // Generate a random IV (Initialization Vector)
                        SecureRandom secureRandom = new SecureRandom();
                        byte[] ivBytes = new byte[16]; // 16 bytes for AES
                        secureRandom.nextBytes(ivBytes);

                        // setup cipher parameters with key and IV
                        KeyParameter keyParam = new KeyParameter(decryptedSessionKey);
                        byte[] messageBytes = message.getBytes("UTF-8");
                        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
                        CipherParameters params = new ParametersWithIV(keyParam, ivBytes);
                        cipher.init(true, params);

                        int blockSize = cipher.getBlockSize();
                        int messageLength = messageBytes.length;


                        dataOutputStream.writeUTF(PayloadTypes.INT.getDataType());
                        dataOutputStream.writeInt(messageLength);
                        dataOutputStream.flush();


                        int paddedLength = ((messageLength + blockSize - 1) / blockSize) * blockSize; // Calculate the padded length

                        byte[] paddedMessageBytes = new byte[paddedLength];
                        System.arraycopy(messageBytes, 0, paddedMessageBytes, 0, messageLength);

                        byte[] encryptedMessageBytes = new byte[cipher.getOutputSize(paddedLength)];
                        int bytesWritten = cipher.processBytes(paddedMessageBytes, 0, paddedLength, encryptedMessageBytes, 0);
                        bytesWritten += cipher.doFinal(encryptedMessageBytes, bytesWritten);

                        // Encode the entire encryptedMessageBytes
                        String encryptedMessageString = Base64.getEncoder().encodeToString(encryptedMessageBytes);
                        // Send the length of the IV followed by the IV itself
                        System.out.println("SENDING ivBytes.length:");
                        System.out.println(ivBytes.length);
                        dataOutputStream.writeUTF(PayloadTypes.INT.getDataType());
                        dataOutputStream.flush();
                        dataOutputStream.writeInt(ivBytes.length);
                        dataOutputStream.flush();
                        System.out.println("SENDING ivBytes:");
                        dataOutputStream.writeUTF(PayloadTypes.BYTES.getDataType());
                        dataOutputStream.flush();
                        System.out.println(Arrays.toString(ivBytes));
                        dataOutputStream.write(ivBytes);
                        dataOutputStream.flush();

                        // Send the length of the encrypted message followed by the encoded message itself
                        System.out.println("SENDING encryptedMessageBytes.length:");
                        System.out.println(encryptedMessageBytes.length);
                        dataOutputStream.writeUTF(PayloadTypes.INT.getDataType());
                        dataOutputStream.flush();
                        dataOutputStream.writeInt(encryptedMessageBytes.length);
                        dataOutputStream.flush();

                        System.out.println("SENDING encryptedMessageBytes:");
                        System.out.println(Arrays.toString(encryptedMessageBytes));
                        dataOutputStream.writeUTF(PayloadTypes.BYTES.getDataType());
                        dataOutputStream.flush();
                        dataOutputStream.write(encryptedMessageBytes);
                        dataOutputStream.flush();

                    }catch (InvalidCipherTextException e) {
                        System.err.println("Encryption failed: " + e.getMessage());
                    }

                }

                if (message.equalsIgnoreCase("exit")) {
                    break;
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

