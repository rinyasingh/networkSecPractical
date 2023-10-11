import java.io.*;
import java.net.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.X509CertPairParser;

import keys.KeyUtils;
public class Server {
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        int port = 5001;
        boolean serverRunning = true;

        X509Certificate aliceCert = null;
        X509Certificate caCert = null;
        X509Certificate bobCert = null;
        X509Certificate serverCert = null;
        // Boolean aliceVer = true;
        // Boolean bobVer = true;
        // Boolean caVer = true;
        try {
            aliceCert = KeyUtils.readX509Certificate("alice");
            bobCert = KeyUtils.readX509Certificate("bob");
            caCert = KeyUtils.readX509Certificate("ca");
            serverCert = KeyUtils.readX509Certificate("server");
            aliceCert.verify(caCert.getPublicKey());
            bobCert.verify(caCert.getPublicKey());
            caCert.verify(caCert.getPublicKey());
        } catch (Exception e) {
            System.err.println("NOPE");
            e.printStackTrace();
            // aliceVer = false;
            // bobVer = false;
            // caVer= false;
        }
        // System.out.println("Alice: " + aliceVer);
        // System.out.println("Bob: " + bobVer);
        // System.out.println("CA: " + caVer);
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
