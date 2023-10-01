import java.io.*;
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Scanner;
import java.security.*;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;

public class Alice {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

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
                        byte[] decryptedData = cipher.doFinal(cipherText);


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

                //Convert message to bytes
                byte[] data = message.getBytes();

                // Generate AES key for message encryption
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES",new BouncyCastleProvider());
                keyGenerator.init(256); // Key size (adjust as needed)
                SecretKey aesKey = keyGenerator.generateKey();

                // Encrypt data with AES - https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf
                Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding",new BouncyCastleProvider());
                aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);
                byte[] aesEncryptedData = aesCipher.doFinal(data);

                // Encrypt AES key with RSA public key - https://www.bouncycastle.org/fips-java/BCFipsIn100.pdf
                KeyPairGenerator keyPair = KeyPairGenerator.getInstance("RSA");
                keyPair.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F4));
                KeyPair rsaKeyPair = keyPair.generateKeyPair();

                Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding",new BouncyCastleProvider());
                rsaCipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPrivate());
                byte[] rsaEncryptedKey = rsaCipher.doFinal(aesKey.getbytes());

                //I am very confused so this is what I understand and what I did here
                //"generate shared keys for symmetric encryption (e.g., DES, AES)" that's only one (aes) key used to directly encrypt the message, which is done (I think it will be the same one used to decrypt the message too)
                //"RSA for public-key encryption" - this is where I'm confused, are we encrypting (1) the aeskey or (2) the message (as like an extra layer of encryption)?
                //if (1): then are we encrypting it with our private key, sending it over and then Bob uses the public key to decrypt the aeskey to then decrypt the aes encrypted message? (That is the code I have for rsa at the moment)
                //if (2): that makes line 70 : byte[] rsaEncryptedData = rsaCipher.doFinal(aesEncryptedData);
                //Also most of this is using java packages instead of bouncy castle (even though I got it all from bouncy castle resources, I think they use the same provider) which I'll look into

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
