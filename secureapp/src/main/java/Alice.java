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

import java.io.FileReader;

public class Alice {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePub;
        PrivateKey alicePriv;
        PublicKey bobPub;

        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());

            dataOutputStream.writeUTF("alice");

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

            // Send the length of the encrypted session key followed by the key itself
            System.out.println("SENDING encryptedsessionkey length:"+encryptedSessionKey.length);
            dataOutputStream.writeUTF(PayloadTypes.INT.getDataType());
            dataOutputStream.writeInt(encryptedSessionKey.length);
            System.out.println("SENDING encryptedsessionkey:"+ Arrays.toString(encryptedSessionKey));
            dataOutputStream.writeUTF(PayloadTypes.BYTES.getDataType());
            dataOutputStream.write(encryptedSessionKey);
            dataOutputStream.flush();

//            System.out.println("encrypted sessionkey: " + encryptedSessionKey);

            //RECEIVE MESSAGES FROM BOB
            Thread bobListener = new Thread(() -> {
                try {
                    while (true) {
//                        String receivedMessage = dataInputStream.readUTF();
//                        System.out.println("Bob: "+ receivedMessage);

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
                            KeyParameter keyParam = new KeyParameter(sessionKey);
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
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                String message = scanner.nextLine();
                System.out.println("SENDING PLAIN MESSAGE:");
                System.out.println(message);

                dataOutputStream.writeUTF(PayloadTypes.UTF.getDataType());
                dataOutputStream.flush();

                dataOutputStream.writeUTF(message);
                dataOutputStream.flush();

                //Checks so it doesn't send empty messages
                if (!message.isEmpty()) {
                    try {
                        // Generate a random IV (Initialization Vector)
                        byte[] ivBytes = new byte[16]; // 16 bytes for AES
                        secureRandom.nextBytes(ivBytes);

                        // setup cipher parameters with key and IV
                        KeyParameter keyParam = new KeyParameter(sessionKey);
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
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e);
            System.out.println(e.getMessage());
        }
    }
}