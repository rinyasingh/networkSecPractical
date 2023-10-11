import java.io.*;
import java.net.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.*;
import org.bouncycastle.jce.provider.X509CertPairParser;

import keys.KeyUtils;
public class Server {
    private static final String serverKeyStorePath = "secureapp/src/main/java/keys/KeyStoreServer";
    private static final String serverKeystorePassword = "123456";
    static PublicKey CAPublicKey;
    
    public static void main(String[] args) {
        int port = 5001;
        boolean serverRunning = true;
        // Verifying 
        try {
            FileInputStream fileInp = new FileInputStream(serverKeyStorePath);
            KeyStore serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            char [] serverPassword = serverKeystorePassword.toCharArray();
            serverKeyStore.load(fileInp, serverPassword);
            CAPublicKey = serverKeyStore.getCertificate("ca").getPublicKey();
            System.out.println("HERE: " +CAPublicKey.toString());
        } catch (KeyStoreException | IOException |NoSuchAlgorithmException |CertificateException e) {
            System.err.println(e.getMessage());
        }



        // X509Certificate caCert = KeyUtils.readX509Certificate();
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started, waiting for Alice and Bob...");

            // Keep the server running until you manually terminate it
            while (serverRunning) {
                // Wait for Alice to connect
                Socket aliceSocket = serverSocket.accept();
                System.out.println("Alice connected");

                // Wait for Bob to connect
                Socket bobSocket = serverSocket.accept();
                System.out.println("Bob connected");

                // Create separate threads for Alice and Bob to handle bidirectional communication
                Thread aliceThread = new Thread(() -> {
                    forwardMessages(aliceSocket, bobSocket);
                });

                Thread bobThread = new Thread(() -> {
                    forwardMessages(bobSocket, aliceSocket);
                });

                aliceThread.start();
                bobThread.start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void forwardMessages(Socket sourceSocket, Socket destinationSocket) {
        try {
            DataOutputStream destinationOut = new DataOutputStream(destinationSocket.getOutputStream());
            DataInputStream sourceIn = new DataInputStream(sourceSocket.getInputStream());

            while (true) {
                // Receive a message from the source socket
                String message = sourceIn.readUTF();

                // Forward the message to the destination socket
                destinationOut.writeUTF(message);

                if (message.equalsIgnoreCase("exit")) {
                    break;
                }
            }

            sourceSocket.close();
            destinationSocket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}