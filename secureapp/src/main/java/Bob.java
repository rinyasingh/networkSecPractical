import java.io.*;
import java.net.*;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Scanner;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class Bob {
    private static final String KEYSTORE_PWORD = "password";
    private static KeyManagerFactory keyManagerFactory;

    public static void loadKeyStore(String keyStorePassword) {
        try { 
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(new FileInputStream("secureapp/config/bob-keystore.jks"), keyStorePassword.toCharArray());

            keyManagerFactory = KeyManagerFactory.getInstance("SunX509");
            keyManagerFactory.init(keyStore, keyStorePassword.toCharArray());

        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | UnrecoverableKeyException e) {
            System.err.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        loadKeyStore(KEYSTORE_PWORD);

        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, null);

            SSLSocketFactory socketFactory = sslContext.getSocketFactory();
            SSLSocket aliceSocket = (SSLSocket) socketFactory.createSocket("localhost", 5001);
            
            aliceSocket.startHandshake();
            Certificate aliceCertificate = aliceSocket.getSession().getPeerCertificates()[0];
            System.out.println("bob: " + aliceCertificate.toString());
            
        } catch (KeyManagementException | NoSuchAlgorithmException | IOException e) {
            System.err.println(e.getMessage());
        }

        try (Socket socket = new Socket("localhost", 5001)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            // Create a separate thread to continuously read and display messages from Alice
            Thread aliceListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();
                        System.out.println(receivedMessage);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            aliceListener.start();

            while (true) {
//                System.out.print("Bob: ");
                String message = scanner.nextLine();

                // Send the message to Alice
                dataOutputStream.writeUTF("Bob: " + message);

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