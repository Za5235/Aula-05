import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.util.Base64;
import java.util.Scanner;

public class CriptografiaExemplo {

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("\n--- MENU ---");
            System.out.println("1. Criptografia Simétrica (AES)");
            System.out.println("2. Criptografia Assimétrica (RSA)");
            System.out.println("3. Função Hash (SHA-256)");
            System.out.println("0. Sair");
            System.out.print("Escolha uma opção: ");
            int opcao = scanner.nextInt();
            scanner.nextLine();

            switch (opcao) {
                case 1:
                    simetricaAES(scanner);
                    break;
                case 2:
                    assimetricaRSA(scanner);
                    break;
                case 3:
                    hashSHA256(scanner);
                    break;
                case 0:
                    System.out.println("Saindo");
                    return;
                default:
                    System.out.println("Opção inválida.");
            }
        }
    }
    public static void simetricaAES(Scanner scanner) throws Exception {
        System.out.print("Digite uma mensagem: ");
        String mensagem = scanner.nextLine();

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128 bits
        SecretKey chave = keyGen.generateKey();

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, chave);
        byte[] criptografado = cipher.doFinal(mensagem.getBytes());
        String base64Criptografado = Base64.getEncoder().encodeToString(criptografado);
        System.out.println("Criptografado (base64): " + base64Criptografado);

        cipher.init(Cipher.DECRYPT_MODE, chave);
        byte[] descriptografado = cipher.doFinal(Base64.getDecoder().decode(base64Criptografado));
        System.out.println("Descriptografado: " + new String(descriptografado));
    }
    public static void assimetricaRSA(Scanner scanner) throws Exception {
        System.out.print("Digite uma mensagem: ");
        String mensagem = scanner.nextLine();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        PublicKey chavePublica = keyPair.getPublic();
        PrivateKey chavePrivada = keyPair.getPrivate();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, chavePublica);
        byte[] criptografado = cipher.doFinal(mensagem.getBytes());
        String base64Criptografado = Base64.getEncoder().encodeToString(criptografado);
        System.out.println("Criptografado (base64): " + base64Criptografado);

        cipher.init(Cipher.DECRYPT_MODE, chavePrivada);
        byte[] descriptografado = cipher.doFinal(Base64.getDecoder().decode(base64Criptografado));
        System.out.println("Descriptografado: " + new String(descriptografado));
    }
    public static void hashSHA256(Scanner scanner) throws Exception {
        System.out.print("Digite uma mensagem para gerar hash: ");
        String mensagem = scanner.nextLine();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(mensagem.getBytes());

        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }

        System.out.println("Hash SHA-256: " + sb.toString());
    }
}

