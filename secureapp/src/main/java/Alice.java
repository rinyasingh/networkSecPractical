import java.io.*;
import java.net.*;
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
            System.out.println("sessionkey: "+sessionKey);

            // Encrypt the session key with Bob's public key using RSA with PKCS1Padding
            byte[] encryptedSessionKey = rsaEngine.processBlock(sessionKey, 0, sessionKey.length);

            // Send the length of the encrypted session key followed by the key itself
//            dataOutputStream.writeInt(encryptedSessionKeyBytes.length);
            dataOutputStream.write(encryptedSessionKey);
            System.out.println("encrypted sessionkey: " + encryptedSessionKey);

            //RECEIVE MESSAGES FROM BOB
            Thread bobListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();
                        System.out.println("Bob: "+ receivedMessage);

                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                String message = scanner.nextLine();
                //Checks so it doesn't send empty messages
                if (!message.isEmpty()) {
//                    dataOutputStream.writeUTF(message);
                    try {
                        // Generate a random IV (Initialization Vector)
                        byte[] ivBytes = new byte[16]; // 16 bytes for AES
                        secureRandom.nextBytes(ivBytes);

                        // setup cipher parameters with key and IV
                        KeyParameter keyParam = new KeyParameter(sessionKey);
                        byte[] messageBytes = message.getBytes("UTF-8");
                        BufferedBlockCipher cipher = new BufferedBlockCipher(new CBCBlockCipher(new AESEngine()));
                        CipherParameters params = new ParametersWithIV(new KeyParameter(sessionKey), ivBytes);
                        cipher.init(true, params);

                        int blockSize = cipher.getBlockSize();
                        int messageLength = messageBytes.length;
                        int paddedLength = ((messageLength + blockSize - 1) / blockSize) * blockSize; // Calculate the padded length

                        byte[] paddedMessageBytes = new byte[paddedLength];
                        System.arraycopy(messageBytes, 0, paddedMessageBytes, 0, messageLength);

                        byte[] encryptedMessageBytes = new byte[cipher.getOutputSize(paddedLength)];
                        int bytesWritten = cipher.processBytes(paddedMessageBytes, 0, paddedLength, encryptedMessageBytes, 0);
                        bytesWritten += cipher.doFinal(encryptedMessageBytes, bytesWritten);

// Encode the entire encryptedMessageBytes
                        String encryptedMessageString = Base64.getEncoder().encodeToString(encryptedMessageBytes);
// Send the length of the IV followed by the IV itself
                        dataOutputStream.writeInt(ivBytes.length);
                        dataOutputStream.flush();

                        dataOutputStream.write(ivBytes);
                        dataOutputStream.flush();

// Send the length of the encrypted message followed by the encoded message itself
//                        dataOutputStream.writeInt(encryptedMessageBytes.length);
//                        dataOutputStream.writeUTF(encryptedMessageString);

                        dataOutputStream.writeInt(encryptedMessageBytes.length);
                        dataOutputStream.flush();
                        dataOutputStream.writeUTF(encryptedMessageString);
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
