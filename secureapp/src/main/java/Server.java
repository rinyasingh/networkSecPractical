import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) {
        int port = 5001; // Choose a port for the server
        boolean serverRunning = true;

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

                // Create threads to handle Alice and Bob's communication
                Thread aliceThread = new Thread(new ClientHandler(aliceSocket, "Alice", bobSocket));
                Thread bobThread = new Thread(new ClientHandler(bobSocket, "Bob", aliceSocket));

                // Start the threads
                aliceThread.start();
                bobThread.start();
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
