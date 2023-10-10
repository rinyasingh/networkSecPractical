import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.KeyStoreException;

public class Server {
    public static void main(String[] args) {
        int port = 5001;
        boolean serverRunning = true;
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            
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

        } catch (IOException | KeyStoreException e) {
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
