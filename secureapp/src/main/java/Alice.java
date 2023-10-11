import java.io.*;
import java.net.*;
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.FileReader;
import java.security.KeyPair;
public class Alice {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePub;
        PrivateKey alicePriv;
        PublicKey bobPub;
        try{

             alicePub = KeyUtils.readPublicKey("alice");
             alicePriv = KeyUtils.readPrivateKey("alice");
             bobPub = KeyUtils.readPublicKey("bob");
        }
        catch (Exception e){
            System.out.println(e);
        }


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
            PublicKey finalBobPub = bobPub;
            Thread bobListener = new Thread(() -> {
                try {
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();
                        System.out.println("Bob: "+ receivedMessage);
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
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                String message = scanner.nextLine();
                //Checks so it doesnt send empty messages
                if (!message.isEmpty()) {
                    dataOutputStream.writeUTF(message);
                }
                if (textMessage.equalsIgnoreCase("exit")) {
                    break;
                }
            }

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}