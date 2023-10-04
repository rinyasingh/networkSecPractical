import java.io.*;
import java.net.*;

public class ClientHandler implements Runnable {
    private Socket socket;
    private String clientName;
    private Socket otherClientSocket; // The socket of the other client
    public ClientHandler(Socket socket, String clientName, Socket otherClientSocket) {
        this.socket = socket;
        this.clientName = clientName;
        this.otherClientSocket = otherClientSocket;
    }

    @Override
    public void run() {
        try {
            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            while (true) {
                // Receive a message from the client
                String receivedMessage = in.readUTF();
//                System.out.println(clientName + ": " + receivedMessage);

                if (otherClientSocket != null) {
                    // Forward the received message to the other client
                    forwardMessageToOtherClient(receivedMessage);
                }

                // Send a response back to the client
//                String response = "Received: " + receivedMessage;
//                out.writeUTF(response);

                if (receivedMessage.equalsIgnoreCase("exit")) {
                    break;
                }
            }

            socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void forwardMessageToOtherClient(String message) {
        try {
            DataOutputStream otherClientOut = new DataOutputStream(otherClientSocket.getOutputStream());
            otherClientOut.writeUTF(message);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}