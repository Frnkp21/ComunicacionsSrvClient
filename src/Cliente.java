import java.io.*;
import java.net.*;
import java.security.*;

public class Cliente {
    private static PublicKey serverPublicKey;
    private static PrivateKey clientPrivateKey;

    public static void main(String[] args) {
        try {
            KeyPair clientKeyPair = MyCryptoUtils.randomGenerate(2048);
            clientPrivateKey = clientKeyPair.getPrivate();

            Socket socket = new Socket("localhost", 1234);
            System.out.println("Conexión establecida con el servidor.");

            ObjectOutputStream outputStream = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream inputStream = new ObjectInputStream(socket.getInputStream());
            serverPublicKey = (PublicKey) inputStream.readObject();

            outputStream.writeObject(clientKeyPair.getPublic());
            outputStream.flush();

            new Thread(new ServerMessageHandler(inputStream)).start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            String input;
            while ((input = reader.readLine()) != null) {
                byte[] encryptedMessage = MyCryptoUtils.encryptData(input.getBytes(), serverPublicKey);
                outputStream.writeObject(encryptedMessage);
                outputStream.flush();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static class ServerMessageHandler implements Runnable {
        private final ObjectInputStream inputStream;

        public ServerMessageHandler(ObjectInputStream inputStream) {
            this.inputStream = inputStream;
        }

        @Override
        public void run() {
            try {
                while (true) {
                    byte[] encryptedMessage = (byte[]) inputStream.readObject();
                    byte[] decryptedMessage = MyCryptoUtils.decryptData(encryptedMessage, clientPrivateKey);
                    System.out.println("Servidor: " + new String(decryptedMessage));
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
