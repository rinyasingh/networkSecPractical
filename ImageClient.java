import java.io.*;
import java.net.*;
import java.util.Scanner;
import java.util.Base64;

public class ImageClient {
    public static void main(String[] args) {
        String serverAddress = "127.0.0.1"; // Replace with your server's IP address
        int serverPort = 3000; // Replace with your server's port

        try {
            Socket socket = new Socket(serverAddress, serverPort);
            OutputStream os = socket.getOutputStream();

            Scanner myObj = new Scanner(System.in); // Create a Scanner object
            System.out.println("Connected to server");
            System.out.println("Please enter the file path: ");

            String filePath = myObj.nextLine(); // Read user input
            System.out.println("File path is: " + filePath); // Output user input

            File imageFile = new File(filePath);
            FileInputStream fis = new FileInputStream(imageFile); // input stream

            // Read and encode the image as Base64
            byte[] buffer = new byte[1024];
            int bytesRead; //tracks the number of bytes read in each iteration.
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            //This loop reads the image data from an input stream,(fis),and stores it in a buffer. 
            //It reads the image data in chunks of buffer.length bytes at a time until it reaches the 
            //end of the input stream.
            while ((bytesRead = fis.read(buffer)) != -1) {
                baos.write(buffer, 0, bytesRead);
            }

            byte[] imageBytes = baos.toByteArray();
            String base64Image = Base64.getEncoder().encodeToString(imageBytes);

            // Send the Base64-encoded image data and name to the server
            PrintWriter out = new PrintWriter(os);
            out.println(imageFile.getName()); // Send the filename

            out.println(base64Image); // Send the Base64-encoded image
            out.flush();

            fis.close();
            os.close();
            socket.close();

            System.out.println("Image sent to the server SUCCESSFULLY.");

        } catch (FileNotFoundException e) {
            System.out.println("Error: File not found.");    
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
