import java.io.*;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import keys.KeyUtils;

import java.io.FileReader;
import java.security.KeyPair;
public class Alice {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        PublicKey alicePub;
        PrivateKey alicePriv;
        PublicKey bobPub;
        try{

             alicePub = KeyUtils.readPublicKey("alice");
             alicePriv = KeyUtils.readPrivateKey("alice");
             bobPub = KeyUtils.readPublicKey("bob");
        }
        catch (Exception e){
            System.out.println(e);
        }


        Scanner scanner = new Scanner(System.in);
        int port = 5001;

        try (Socket socket = new Socket("localhost", port)) {
            DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

            //RECEIVE MESSAGES FROM BOB
            Thread bobListener = new Thread(() -> {
                try {
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    while (true) {
                        String receivedMessage = dataInputStream.readUTF();
                        System.out.println("Bob: "+ receivedMessage);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });
            bobListener.start();

            //SEND MESSAGES TO BOB
            while (true) {
                String message = scanner.nextLine();
                //Checks so it doesnt send empty messages
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
