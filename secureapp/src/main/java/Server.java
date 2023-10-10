import java.io.*;
import java.net.*;
import java.security.Key;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.swing.KeyStroke;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
public class Server {
    private static final String keystorePassword = "password";
   
    public static KeyStore loadKeyStore(String keystorePath, String keystorePassword) {
        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance("JKS");
            FileInputStream keyStoreStream = new FileInputStream(keystorePath);
            keyStore.load(keyStoreStream, keystorePassword.toCharArray());
            return keyStore;
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            System.out.println(e.getMessage());
            return null;
        }
    }
    public static void main(String[] args) {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        int port = 5001; // Choose a port for the server
        boolean serverRunning = true;
        try {
            InputStream keyInput = new FileInputStream("server-keystore.jks");
            KeyStore serverKeyStore =  KeyStore.getInstance(KeyStore.getDefaultType());
            serverKeyStore.load(keyInput, "$3rv3r$3cur3".toCharArray());
        
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("JKS");
            keyManagerFactory.init(serverKeyStore, keystorePassword.toCharArray());

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagerFactory.getKeyManagers(), null, new SecureRandom());

            SSLServerSocketFactory socketFactory = sslContext.getServerSocketFactory();
            SSLServerSocket serverSocket = (SSLServerSocket) socketFactory.createServerSocket(5001);
            SSLSocket aliceSocket = (SSLSocket) serverSocket.accept();
            SSLSocket bobSocket = (SSLSocket) serverSocket.accept();
            
            Certificate aliceCertificate = aliceSocket.getSession().getPeerCertificates()[0];

            DataOutputStream bobOutput = new DataOutputStream(bobSocket.getOutputStream());
            bobOutput.writeUTF(aliceCertificate.toString());
            System.out.println(aliceCertificate.toString());
            Certificate bobCertificate = bobSocket.getSession().getPeerCertificates()[0];

            DataOutputStream aliceOutput = new DataOutputStream(aliceSocket.getOutputStream());
            aliceOutput.writeUTF(bobCertificate.toString());

            serverSocket.close();
            aliceSocket.close();
            bobSocket.close();
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableKeyException | KeyManagementException | IOException e) {
            System.err.println(e.getMessage());;
        }
        // try (ServerSocket serverSocket = new ServerSocket(port)) {
        //     System.out.println("Server started, waiting for Alice and Bob...");
 catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        //     // Keep the server running until you manually terminate it
        //     while (serverRunning) {
        //         // Wait for Alice to connect
        //         Socket aliceSocket = serverSocket.accept();
        //         System.out.println("Alice connected");

        //         // Wait for Bob to connect
        //         Socket bobSocket = serverSocket.accept();
        //         System.out.println("Bob connected");

        //         // Create threads to handle Alice and Bob's communication
        //         Thread aliceThread = new Thread(new ClientHandler(aliceSocket, "Alice", bobSocket));
        //         Thread bobThread = new Thread(new ClientHandler(bobSocket, "Bob", aliceSocket));

        //         // Start the threads
        //         aliceThread.start();
        //         bobThread.start();
        //     }

        // } catch (IOException e) {
        //     e.printStackTrace();
        // }
    }
}