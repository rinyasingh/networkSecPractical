import keys.KeyUtils;

import java.io.*;
import java.net.*;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Scanner;

public class Bob {
    public static void main(String[] args) {


        PublicKey bobPub;
        PrivateKey bobPriv;
        PublicKey alicePub;
        try{

            bobPub = KeyUtils.readPublicKey("bob");
            bobPriv = KeyUtils.readPrivateKey("bob");
            alicePub = KeyUtils.readPublicKey("alice");
        }
        catch (Exception e){
            System.out.println(e);
        }

        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            //RECEIVE MESSAGES FROM ALICE
            Thread aliceListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();
                        System.out.println("Alice: " + receivedMessage);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            aliceListener.start();

            //SEND MESSAGES TO ALICE
            while (true) {
                String message = scanner.nextLine();
                // Check so it doesnt send empty messages
                if (!message.isEmpty()) {
                    dataOutputStream.writeUTF(message);
                }

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
