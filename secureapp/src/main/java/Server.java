import java.io.*;
import java.net.*;

import java.security.KeyStore;
import java.security.KeyStoreException;

public class Server {
    public static void main(String[] args) {
        int port = 5001;

        boolean isFirstToConnect = false;
        boolean serverRunning = true;

        try (ServerSocket serverSocket = new ServerSocket(port)) {
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            
            System.out.println("Server started, waiting for Alice and Bob...");

            // Keep the server running until you manually terminate it
            while (serverRunning) {
                Socket aliceSocket = null;
                DataInputStream aliceInput = null;
                Socket bobSocket  = null;
                DataInputStream bobInput = null;

                // Wait for first user to connect
                Socket tempSocket = serverSocket.accept();
                DataInputStream tempInputStream = new DataInputStream(tempSocket.getInputStream());
                String userA = tempInputStream.readUTF();

                if(userA.equals("alice"))
                {
                    aliceSocket = tempSocket;
                    aliceInput =  tempInputStream;
                    System.out.println("Alice connected");
                    isFirstToConnect = true;
                    try {
                        System.out.println("SENDING TRUE TO ALICE");
                        DataOutputStream aliceOutput = new DataOutputStream(aliceSocket.getOutputStream());
                        aliceOutput.writeBoolean(isFirstToConnect);
                    } catch (IOException e) {
                        System.out.println(e.getMessage());
                    }

                }
                else if(userA.equals("bob"))
                {
                    bobSocket = tempSocket;
                    bobInput =  tempInputStream;
                    System.out.println("Bob connected");
                    isFirstToConnect = true;
                    try {
                        System.out.println("SENDING TRUE TO BOB");
                        DataOutputStream bobOutput = new DataOutputStream(bobSocket.getOutputStream());
                        bobOutput.writeBoolean(isFirstToConnect);
                    } catch (IOException e) {
                        System.out.println(e.getMessage());
                    }
                }

                
                // Wait for second user to connect
                tempSocket = serverSocket.accept();
                tempInputStream = new DataInputStream(tempSocket.getInputStream());
                String userB = tempInputStream.readUTF();
                if(userB.equals("alice"))
                {
                    aliceSocket = tempSocket;
                    aliceInput =  tempInputStream;
                    System.out.println("Alice connected");

                    isFirstToConnect = false;
                    try {
                        System.out.println("SENDING FALSE TO ALICE");
                        DataOutputStream aliceOutput = new DataOutputStream(aliceSocket.getOutputStream());
                    aliceOutput.writeBoolean(isFirstToConnect);
                    } catch (IOException e) {
                        System.out.println(e.getMessage());
                    }

                }
                else if(userB.equals("bob"))
                {
                    bobSocket = tempSocket;
                    bobInput =  tempInputStream;
                    System.out.println("Bob connected");

                    isFirstToConnect = false;
                    try {
                        System.out.println("SENDING FALSE TO BOB");
                        DataOutputStream bobOutput = new DataOutputStream(bobSocket.getOutputStream());
                        bobOutput.writeBoolean(isFirstToConnect);
                    } catch (IOException e) {
                        System.out.println(e.getMessage());
                    }


                }

                // Create separate threads for Alice and Bob to handle bidirectional communication
                // Need to declare new sockets here because lambda expression needs
                // variables that are final or effectively final
                Socket finalAliceSocket = aliceSocket;
                Socket finalBobSocket = bobSocket;
                DataInputStream finalAliceInput = aliceInput;
                DataInputStream finalBobInput = bobInput;

                Thread aliceThread = new Thread(() -> {
                    forwardMessages(finalAliceSocket, finalBobSocket, finalAliceInput);
                });
                Thread bobThread = new Thread(() -> {
                    forwardMessages(finalBobSocket, finalAliceSocket, finalBobInput);
                });

                aliceThread.start();
                bobThread.start();
            }

        } catch (IOException | KeyStoreException e) {
            System.out.println(e.getMessage());
        }
    }

    private static void forwardMessages(Socket sourceSocket, Socket destinationSocket, DataInputStream sourceIn ) {
        try {
            DataOutputStream destinationOut = new DataOutputStream(destinationSocket.getOutputStream());

            while (true) {
                // Receive a message from the source socket
                String message = sourceIn.readUTF();

                 // Forward the message to the destination socket
                destinationOut.writeUTF(message);

            }


        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
    }

    