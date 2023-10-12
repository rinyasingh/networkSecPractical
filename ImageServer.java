import java.io.*;
import java.net.*;
import java.util.Base64;

public class ImageServer {
    public static void main(String[] args) {
        int serverPort = 3000;
        boolean door = true;
        try {
            ServerSocket serverSocket = new ServerSocket(serverPort);
            System.out.println("Server is waiting for the image...");

            while (door) {
                Socket clientSocket = serverSocket.accept();
                InputStream is = clientSocket.getInputStream(); // used to receive data from the client

                // Read the Base64-encoded image data as a string
                BufferedReader reader = new BufferedReader(new InputStreamReader(is));

                // Read the filename from the client
                String receivedFileName1 = reader.readLine();
                if (receivedFileName1 == null){
                    System.out.println("The file was not found, no file received.");
                }else{
                    // changing the file name to prevent overwriting
                    String receivedFileName = "received_"+receivedFileName1;
                    
                    // Read the Base64-encoded image data as a string
                    StringBuilder base64ImageBuilder = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        base64ImageBuilder.append(line);
                    }

                    // Decode the Base64 data
                    byte[] decodedImage = Base64.getDecoder().decode(base64ImageBuilder.toString());

                    // take the binary data (the image in the form of a byte array) and writes it to the file
                    File receivedImage = new File(receivedFileName);
                    FileOutputStream fos = new FileOutputStream(receivedImage);
                    fos.write(decodedImage);
                    fos.close();
                    
                    System.out.println("Image received and saved as: " + receivedFileName);
                    
                    reader.close();
                    clientSocket.close();
                    door = false;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
