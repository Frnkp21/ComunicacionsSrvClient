import java.io.*;
import java.net.*;
import java.security.*;

public class Server {
    private static PublicKey clientPublicKey;
    private static PrivateKey serverPrivateKey;

    public static void main(String[] args) {
        try {
            KeyPair serverKeyPair = MyCryptoUtils.randomGenerate(2048);
            serverPrivateKey = serverKeyPair.getPrivate();

            ServerSocket serverSocket = new ServerSocket(1234);

            System.out.println("Servidor iniciado. Esperando conexiones...");

            Socket clientSocket = serverSocket.accept();
            System.out.println("Cliente conectado.");

            ObjectInputStream inputStream = new ObjectInputStream(clientSocket.getInputStream());
            ObjectOutputStream outputStream = new ObjectOutputStream(clientSocket.getOutputStream());

            outputStream.writeObject(serverKeyPair.getPublic());
            outputStream.flush();

            clientPublicKey = (PublicKey) inputStream.readObject();

            new Thread(new ClientMessageHandler(inputStream)).start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String input;
            while ((input = reader.readLine()) != null) {
                byte[] encryptedMessage = MyCryptoUtils.encryptData(input.getBytes(), clientPublicKey);
                outputStream.writeObject(encryptedMessage);
                outputStream.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class ClientMessageHandler implements Runnable {
        private final ObjectInputStream inputStream;

        public ClientMessageHandler(ObjectInputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    byte[] encryptedMessage = (byte[]) inputStream.readObject();
                    byte[] decryptedMessage = MyCryptoUtils.decryptData(encryptedMessage, serverPrivateKey);
                    System.out.println("Cliente: " + new String(decryptedMessage));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
