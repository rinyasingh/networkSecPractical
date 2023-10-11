import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.X509CertPairParser;
import java.util.Arrays;

import static java.lang.System.exit;
import java.security.KeyStore;
import java.security.KeyStoreException;

import keys.KeyUtils;
public class Server {
    public static void main(String[] args) {
        int port = 5001;
        boolean serverRunning = true;
        // X509Certificate caCert = KeyUtils.readX509Certificate();
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
                }
                else if(userA.equals("bob"))
                {
                    bobSocket = tempSocket;
                    bobInput =  tempInputStream;
                    System.out.println("Bob connected");
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
                }
                else if(userB.equals("bob"))
                {
                    bobSocket = tempSocket;
                    bobInput =  tempInputStream;
                    System.out.println("Bob connected");
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
            e.printStackTrace();
        }
    }

    private static void forwardMessages(Socket sourceSocket, Socket destinationSocket, DataInputStream sourceIn ) {
        try {
            DataOutputStream destinationOut = new DataOutputStream(destinationSocket.getOutputStream());
//            DataInputStream sourceIn = new DataInputStream(sourceSocket.getInputStream());
            int bytesToRead = 0;
            while (true) {
                String input =sourceIn.readUTF();
//                System.out.println("INPUT TYPE: "+input);
                PayloadTypes type =  PayloadTypes.fromString(input);
                System.out.println("INPUT TYPE: "+input+ " " + "Created TYPE: "+type);
                switch (type) {
                    case UTF :
                        String stringMessage = sourceIn.readUTF();
                        System.out.println("STRING MESSAGE: "+stringMessage);
                        destinationOut.writeUTF(stringMessage);
                        destinationOut.flush();

                        if (stringMessage.equalsIgnoreCase("exit")) {
                            exit(0);
                            sourceSocket.close();
                            destinationSocket.close();
                        }
                        break;
                    case INT:
                        int intMessage = sourceIn.readInt();
                        System.out.println("INT MESSAGE: "+ intMessage);
                        bytesToRead = intMessage;
                        destinationOut.writeInt(intMessage);
                        destinationOut.flush();

                        break;
                    case BYTES:
                        byte[] bytesMessage = sourceIn.readNBytes(bytesToRead);
                        System.out.println("BYTES MESSAGE ["+bytesToRead+"bytes]: "+ Arrays.toString(bytesMessage));
                        destinationOut.write(bytesMessage);
                        destinationOut.flush();
                        break;

                }

//                System.out.println("SERVER RECEIVED MESSAGE:");
//                // Receive a message from the source socket
//                String message = sourceIn.readUTF();
//                int msg = sourceIn.readInt();
//
//                System.out.println(message);
//                System.out.println(msg);
//
//                // Forward the message to the destination socket
//                destinationOut.writeUTF(message);
//                destinationOut.writeInt(msg);

            }


        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    }

    