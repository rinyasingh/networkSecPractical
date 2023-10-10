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
import java.util.Arrays;
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
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}

