import java.io.*;
import java.net.*;

public class Server {
    public static void main(String[] args) {
        int port = 5001;
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
            System.out.println("HELLO");
            System.out.println("sourceSocket" + sourceSocket.toString());
            System.out.println("destinationSocket"+ destinationSocket.toString());

            while (true) {
                // Receive a message from the source socket
                String message = sourceIn.readUTF();
                System.out.println("message");

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

//
//import java.io.*;
//import java.net.*;
//
//public class Server {
//    public static void main(String[] args) {
//        int port = 5001;
//        boolean serverRunning = true;
//
//        try (ServerSocket serverSocket = new ServerSocket(port)) {
//            System.out.println("Server started, waiting for Alice and Bob...");
//
//            // Wait for Alice to connect
//            Socket aliceSocket = serverSocket.accept();
//            System.out.println("Alice connected");
//
//            // Wait for Bob to connect
//            Socket bobSocket = serverSocket.accept();
//            System.out.println("Bob connected");
//
//            // Create separate threads for Alice and Bob to handle bidirectional communication
//            Thread aliceThread = new Thread(() -> {
//                forwardMessages(aliceSocket, bobSocket);
//            });
//
//            Thread bobThread = new Thread(() -> {
//                forwardMessages(bobSocket, aliceSocket);
//            });
//
//            aliceThread.start();
//            bobThread.start();
//
//            // Keep the server running until you manually terminate it
//            while (serverRunning) {
//                // You can add any additional server logic here
//            }
//
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//
//    private static void forwardMessages(Socket sourceSocket, Socket destinationSocket) {
//        try {
//            System.out.println("HELLO");
//            System.out.println("sourceSocket" + sourceSocket.toString());
//            System.out.println("destinationSocket"+ destinationSocket.toString());
//            DataOutputStream destinationOut = new DataOutputStream(destinationSocket.getOutputStream());
//            DataInputStream sourceIn = new DataInputStream(sourceSocket.getInputStream());
//
//            while (true) {
//                System.out.println("SENDING?");
//
//                // Receive a message from the source socket
//                String message = sourceIn.readUTF();
//
//                // Forward the message to the destination socket
//                destinationOut.writeUTF(message);
//
//                if (message.equalsIgnoreCase("exit")) {
//                    break;
//                }
//            }
//
//            sourceSocket.close();
//            destinationSocket.close();
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
//    }
//}
