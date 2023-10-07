//import keys.KeyUtils;
//import org.bouncycastle.crypto.BufferedBlockCipher;
//import org.bouncycastle.crypto.CipherParameters;
//import org.bouncycastle.crypto.InvalidCipherTextException;
//import org.bouncycastle.crypto.engines.AESEngine;
//import org.bouncycastle.crypto.engines.RSAEngine;
//import org.bouncycastle.crypto.modes.CBCBlockCipher;
//import org.bouncycastle.crypto.paddings.PKCS7Padding;
//import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
//import org.bouncycastle.crypto.params.KeyParameter;
//import org.bouncycastle.crypto.params.ParametersWithIV;
//import org.bouncycastle.crypto.params.RSAKeyParameters;
//import org.bouncycastle.crypto.util.PrivateKeyFactory;
//import org.bouncycastle.crypto.util.PublicKeyFactory;
//
//import java.io.*;
//import java.net.*;
//import java.nio.charset.StandardCharsets;
//import java.security.PrivateKey;
//import java.security.PublicKey;
//import java.util.Base64;
//import java.util.Scanner;
//
//public class Bob {
//    public static void main(String[] args) {
//        PublicKey bobPub;
//        PrivateKey bobPriv;
//        PublicKey alicePub;
//
//        Scanner scanner = new Scanner(System.in);
//        int port = 5001;
//
//        try (Socket socket = new Socket("localhost", port)) {
//            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
//            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
//
////          bobPub = KeyUtils.readPublicKey("bob");
//            bobPriv = KeyUtils.readPrivateKey("bob");
////          alicePub = KeyUtils.readPublicKey("alice");
//
//            // Initialize the RSA engine
//            RSAKeyParameters rsaPrivateKey = (RSAKeyParameters) PrivateKeyFactory.createKey(bobPriv.getEncoded());
//            RSAEngine rsaEngine = new RSAEngine();
//            rsaEngine.init(false, rsaPrivateKey);
//
//            // RECEIVE THE ENCRYPTED SESSION KEY
//            int encryptedSessionKeyLength = dataInputStream.readInt();
//            byte[] encryptedSessionKeyBytes = new byte[encryptedSessionKeyLength];
//            dataInputStream.readFully(encryptedSessionKeyBytes);
//            System.out.println(encryptedSessionKeyBytes);
//
//            // DECRYPT THE SESSION KEY WITH BOB'S PRIVATE KEY
//            byte[] sessionKeyBytes = rsaEngine.processBlock(encryptedSessionKeyBytes, 0, encryptedSessionKeyLength);
//            System.out.println(sessionKeyBytes);
//
//            //RECEIVE MESSAGES FROM ALICE
//            Thread aliceListener = new Thread(() -> {
////                try {
////                    while (true) {
////                        try {
////                            //String receivedMessage = dataInputStream.readUTF();
//////                            String encryptedMessageString = dataInputStream.readUTF();
////                            System.out.println("encryptedMessageString");
////
////                            // RECEIVE THE IV
////                            int ivLength = dataInputStream.readInt();
////                            byte[] ivBytes = new byte[ivLength];
////                            dataInputStream.readFully(ivBytes);
////
////                            // RECEIVE THE ENCRYPTED MESSAGE LENGTH AND ENCODED MESSAGE
////                            int encryptedMessageLength = dataInputStream.readInt();
////                            byte[] encryptedMessageBytes = new byte[encryptedMessageLength];
////                            dataInputStream.readFully(encryptedMessageBytes);
////                            System.out.println(encryptedMessageBytes);
////
////                            // DECODE THE ENCRYPTED MESSAGE
////                            String ivString = new String(ivBytes, "UTF-8");
////                            String encryptedMessageString = new String(encryptedMessageBytes, "UTF-8");
////                            byte[] ivDecoded = Base64.getDecoder().decode(ivString);
////                            byte[] encryptedMessageDecoded = Base64.getDecoder().decode(encryptedMessageString);
////                            System.out.println(encryptedMessageDecoded);
////
////                            // Decrypt the message with the session key and IV
////                            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
////                            CipherParameters params = new ParametersWithIV(new KeyParameter(sessionKeyBytes), ivDecoded);
////                            cipher.init(false, params);
////                            byte[] decryptedMessageBytes = new byte[cipher.getOutputSize(encryptedMessageDecoded.length)];
////                            int bytesWritten = cipher.processBytes(encryptedMessageDecoded, 0, encryptedMessageDecoded.length, decryptedMessageBytes, 0);
////                            cipher.doFinal(decryptedMessageBytes, bytesWritten);
////                            System.out.println(decryptedMessageBytes);
////
////                            // Convert the decrypted message bytes to a string
////                            String receivedMessage = new String(decryptedMessageBytes, "UTF-8");;
////                            System.out.println("Alice: " + receivedMessage);
////
////                        } catch (InvalidCipherTextException e) {
////                            System.err.println("Decryption failed: " + e.getMessage());
////                        }
////                    }
////                } catch (IOException e) {
////                    e.printStackTrace();
////                }
//                try {
////                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
//
//                    while (true) {
//                        // Read the IV length and IV
//                        int ivLength = dataInputStream.readInt();
//                        byte[] ivBytes = new byte[ivLength];
//                        dataInputStream.readFully(ivBytes);
//
//                        // Read the encrypted message length and the encoded message
//                        int encryptedMessageLength = dataInputStream.readInt();
//                        byte[] encryptedMessageBytes = new byte[encryptedMessageLength];
//                        dataInputStream.readFully(encryptedMessageBytes);
//
//                        // Decode the received message
//                        String encryptedMessageString = new String(encryptedMessageBytes, StandardCharsets.UTF_8);
//                        byte[] encryptedMessage = Base64.getDecoder().decode(encryptedMessageString);
//
//                        // Decrypt the message
//                        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
//                        CipherParameters params = new ParametersWithIV(new KeyParameter(sessionKeyBytes), ivBytes);
//                        cipher.init(false, params);
//
//                        byte[] decryptedMessageBytes = new byte[cipher.getOutputSize(encryptedMessage.length)];
//                        int bytesWritten = cipher.processBytes(encryptedMessage, 0, encryptedMessage.length, decryptedMessageBytes, 0);
//                        bytesWritten += cipher.doFinal(decryptedMessageBytes, bytesWritten);
//
//                        String decryptedMessage = new String(decryptedMessageBytes, 0, bytesWritten, StandardCharsets.UTF_8);
//
//                        System.out.println("Alice: " + decryptedMessage);
//                    }
//                } catch (IOException | InvalidCipherTextException e) {
//                    System.out.println(e);
//                    e.printStackTrace();
//                }
//
//            });
//            aliceListener.start();
//
//            //SEND MESSAGES TO ALICE
//            while (true) {
//                String message = scanner.nextLine();
//                // Check so it doesn't send empty messages
//                if (!message.isEmpty()) {
//                    dataOutputStream.writeUTF(message);
//                }
//
//                if (message.equalsIgnoreCase("exit")) {
//                    break;
//                }
//            }
//
//            socket.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//}
import keys.KeyUtils;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
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
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            //bobPub = KeyUtils.readPublicKey("bob");
            bobPriv = KeyUtils.readPrivateKey("bob");
            //alicePub = KeyUtils.readPublicKey("alice");

            // Initialize the RSA engine
            RSAEngine rsaEngine = new RSAEngine();

            // RECEIVE THE ENCRYPTED SESSION KEY
            int encryptedSessionKeyLength = dataInputStream.readInt();
            byte[] encryptedSessionKeyBytes = new byte[encryptedSessionKeyLength];
            dataInputStream.readFully(encryptedSessionKeyBytes);

            // DECRYPT THE SESSION KEY WITH BOB'S PRIVATE KEY
            byte[] sessionKeyBytes = rsaEngine.processBlock(encryptedSessionKeyBytes, 0, encryptedSessionKeyLength);

            //RECEIVE MESSAGES FROM ALICE
            Thread aliceListener = new Thread(() -> {
                try {
                    while (true) {
                        // Read the IV length and IV
                        int ivLength = dataInputStream.readInt();
                        byte[] ivBytes = new byte[ivLength];
                        dataInputStream.readFully(ivBytes);

                        // Read the encrypted message length
                        int encryptedMessageLength = dataInputStream.readInt();
                        byte[] encryptedMessageBytes = new byte[encryptedMessageLength];
                        System.out.println(encryptedMessageBytes);
                        dataInputStream.readFully(encryptedMessageBytes);

                        // Decrypt the message
                        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
                        CipherParameters params = new ParametersWithIV(new KeyParameter(sessionKeyBytes), ivBytes);
                        cipher.init(false, params);

                        byte[] decryptedMessageBytes = new byte[cipher.getOutputSize(encryptedMessageBytes.length)];
                        int bytesWritten = cipher.processBytes(encryptedMessageBytes, 0, encryptedMessageBytes.length, decryptedMessageBytes, 0);
                        bytesWritten += cipher.doFinal(decryptedMessageBytes, bytesWritten);

                        String decryptedMessage = new String(decryptedMessageBytes, 0, bytesWritten, StandardCharsets.UTF_8);

                        System.out.println("Alice: " + decryptedMessage);
                    }
                } catch (IOException | InvalidCipherTextException e) {
                    e.printStackTrace();
                }
            });
            aliceListener.start();

            //SEND MESSAGES TO ALICE
            while (true) {
                String message = scanner.nextLine();
                // Check so it doesn't send empty messages
                if (!message.isEmpty()) {
                    dataOutputStream.writeUTF(message);
                }

                if (message.equalsIgnoreCase("exit")) {
                    break;
                }
            }

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
