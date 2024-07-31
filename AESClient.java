import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Scanner;
import java.util.Arrays;

public class AESClient {
    private SecretKey key;
    private final int KEY_SIZE = 128;
    private final int T_LEN = 128;
    private Cipher encryptionCipher;
    private byte[] IV;

    public void init() throws Exception {
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(KEY_SIZE);
        key = generator.generateKey();
    }

    public void initFromString(String secretKey, String iv) {
        key = new SecretKeySpec(decode(secretKey), "AES");
        this.IV = decode(iv);
    }

    public String encrypt(String message) throws Exception {
        byte[] messageInBytes = message.getBytes();
        encryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        encryptionCipher.init(Cipher.ENCRYPT_MODE, key);
        IV = encryptionCipher.getIV();
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        return encode(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        byte[] messageInBytes = decode(encryptedMessage);
        Cipher decryptionCipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(T_LEN, IV);
        decryptionCipher.init(Cipher.DECRYPT_MODE, key, spec);
        byte[] decryptedBytes = decryptionCipher.doFinal(messageInBytes);
        return new String(decryptedBytes);
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            AESClient aesClient = new AESClient();

            System.out.println("Enter true to input key and IV, false to generate them:");
            boolean inputFlag = scanner.nextBoolean();
            scanner.nextLine();  // Consume the newline

            if (inputFlag) {
                System.out.println("Enter the AES key (Base64 encoded):");
                String aesKey = scanner.nextLine();

                System.out.println("Enter the Initialization Vector (IV) (Base64 encoded):");
                String iv = scanner.nextLine();

                aesClient.initFromString(aesKey, iv);
            } else {
                aesClient.init();
            }

            System.out.println("Enter the string to be encrypted:");
            String inputString = scanner.nextLine();

            String encryptedMessage = aesClient.encrypt(inputString);
            String decryptedMessage = aesClient.decrypt(encryptedMessage);

            System.out.println("Encrypted Message: " + encryptedMessage);
            System.out.println("Decrypted Message: " + decryptedMessage);
            
                System.out.println("\nAES Key (Base64): " + aesClient.encode(aesClient.key.getEncoded()));
                System.out.println("AES Key (Decoded Byte Array): " + Arrays.toString(aesClient.key.getEncoded()));
                System.out.println("\nInitialization Vector (IV) (Base64): " + aesClient.encode(aesClient.IV));
                System.out.println("Initialization Vector (IV) (Decoded Byte Array): " + Arrays.toString(aesClient.IV));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
