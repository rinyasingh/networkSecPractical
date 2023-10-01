import java.io.*;
import java.net.*;
import java.util.Scanner;

public class Bob {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

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
