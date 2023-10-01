import java.io.*;
import java.net.*;
import java.util.Scanner;

public class Alice {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        try (Socket socket = new Socket("localhost", 5001)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            // Create a separate thread to continuously read and display messages from Bob
            Thread bobListener = new Thread(() -> {
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
            bobListener.start();

            while (true) {
//                System.out.print("Alice: ");
                String message = scanner.nextLine();

                // Send the message to Bob
                dataOutputStream.writeUTF("Alice: " + message);

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
