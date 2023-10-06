import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Scanner;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;

public class Alice {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        //I think we need to add a few steps to connect the client's and exchange public keys
        //Or to get them from the CA rather

        try (Socket socket = new Socket("localhost", 5001)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            // Create a separate thread to continuously read and display messages from Bob
            Thread bobListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();

                        // Decrypt data with AES
                        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS7Padding",new BouncyCastleProvider()); //https://stackoverflow.com/questions/15925029/aes-encrypt-decrypt-with-bouncy-castle-provider
                        cipher.init(Cipher.DECRYPT_MODE, key);
//                        byte[] decryptedData = cipher.doFinal(receivedMessage);


                        System.out.println(receivedMessage);
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
                }
            });
            bobListener.start();

            while (true) {
//                System.out.print("Alice: ");
                String message = scanner.nextLine();

                //1. Hash message

                //Convert message to bytes
                byte[] data = message.getBytes();


                //2. ENCRYPT HASHED MESSAGE WITH PRIVATE KEY




                //3.  Generate AES key for message encryption (encrypt (2))
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES",new BouncyCastleProvider());
                keyGenerator.init(256); // Key size (adjust as needed)
                SecretKey aesKey = keyGenerator.generateKey();

                //4. Encrypt data with AES - https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding",new BouncyCastleProvider());
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] aesEncryptedData = aesCipher.doFinal(data);

                //5. Encrypt AES symmetric key with RECIPIENT'S RSA public key - https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf
                //This needs to be changed to use the recipient's public key
                KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");
                keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
                KeyPair rsaKeyPair = keyPair.generateKeyPair();

                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",new BouncyCastleProvider());
                rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPrivate());
                byte[] rsaEncryptedKey = rsaCipher.doFinal(aesKey.getEncoded());


                // Send the message to Bob
                dataOutputStream.writeUTF("Alice: " + message);

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
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
    }
}
