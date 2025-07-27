package com.example.securetoken;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;

public class SecureTokenTransmitter {

    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final String RSA_ALGORITHM = "RSA/ECB/PKCS1Padding";
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int AES_KEY_SIZE = 256;
    private static final int IV_SIZE = 16;

    public static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    public byte[] createSecurePayload(String token, PrivateKey senderPrivateKey, PublicKey receiverPublicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(senderPrivateKey);
        byte[] tokenBytes = token.getBytes("UTF-8");
        signature.update(tokenBytes);
        byte[] digitalSignature = signature.sign();

        SignedToken signedToken = new SignedToken(tokenBytes, digitalSignature);
        byte[] signedTokenBytes = serialize(signedToken);


        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE);
        SecretKey sessionKey = keyGen.generateKey();

        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.ENCRYPT_MODE, receiverPublicKey);
        byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(iv));
        byte[] encryptedData = aesCipher.doFinal(signedTokenBytes);

        SecurePayload payload = new SecurePayload(encryptedSessionKey, iv, encryptedData);
        return serialize(payload);
    }


    public String receiveAndVerifyPayload(byte[] payloadBytes, PrivateKey receiverPrivateKey, PublicKey senderPublicKey) throws Exception {
        SecurePayload payload = (SecurePayload) deserialize(payloadBytes);


        Cipher rsaCipher = Cipher.getInstance(RSA_ALGORITHM);
        rsaCipher.init(Cipher.DECRYPT_MODE, receiverPrivateKey);
        byte[] sessionKeyBytes = rsaCipher.doFinal(payload.getEncryptedSessionKey());
        SecretKey sessionKey = new SecretKeySpec(sessionKeyBytes, 0, sessionKeyBytes.length, "AES");

        Cipher aesCipher = Cipher.getInstance(AES_ALGORITHM);
        aesCipher.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(payload.getInitializationVector()));
        byte[] signedTokenBytes = aesCipher.doFinal(payload.getEncryptedData());

        SignedToken signedToken = (SignedToken) deserialize(signedTokenBytes);

        Signature signatureVerifier = Signature.getInstance(SIGNATURE_ALGORITHM);
        signatureVerifier.initVerify(senderPublicKey);
        signatureVerifier.update(signedToken.getData());

        if (signatureVerifier.verify(signedToken.getSignature())) {
            return new String(signedToken.getData(), "UTF-8");
        } else {
            throw new SecurityException("Signature verification failed! The token is compromised or forged.");
        }
    }

    private byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        try (ObjectOutputStream objectStream = new ObjectOutputStream(byteStream)) {
            objectStream.writeObject(obj);
        }
        return byteStream.toByteArray();
    }

    private Object deserialize(byte[] bytes) throws IOException, ClassNotFoundException {
        ByteArrayInputStream byteStream = new ByteArrayInputStream(bytes);
        try (ObjectInputStream objectStream = new ObjectInputStream(byteStream)) {
            return objectStream.readObject();
        }
    }

    public static void main(String[] args) {
        try {
            SecureTokenTransmitter transmitter = new SecureTokenTransmitter();

            KeyPair aliceKeyPair = generateRsaKeyPair();
            KeyPair bobKeyPair = generateRsaKeyPair();

            String originalToken = "user_id:12345;roles:admin,editor;exp:1678886400";
            System.out.println("Исходный токен: " + originalToken + "\n");

            System.out.println("--- Сценарий 1: Успешная передача ---");
            byte[] securePayload = transmitter.createSecurePayload(
                    originalToken,
                    aliceKeyPair.getPrivate(),
                    bobKeyPair.getPublic()
            );
            System.out.println("Зашифрованный пакет готов к отправке (длина: " + securePayload.length + " байт).");

            String receivedToken = transmitter.receiveAndVerifyPayload(
                    securePayload,
                    bobKeyPair.getPrivate(),
                    aliceKeyPair.getPublic()
            );
            System.out.println("Пакет успешно получен и проверен. Расшифрованный токен: " + receivedToken);
            System.out.println("Статус: УСПЕХ\n");

            System.out.println("--- Сценарий 2: Попытка подмены данных ---");
            securePayload[securePayload.length / 2]++;
            System.out.println("Злоумышленник изменил байт в зашифрованном пакете.");
            try {
                transmitter.receiveAndVerifyPayload(securePayload, bobKeyPair.getPrivate(), aliceKeyPair.getPublic());
            } catch (Exception e) {
                System.out.println("Боб не смог обработать пакет. Ошибка: " + e.getClass().getSimpleName() + " - " + e.getMessage());
                System.out.println("Статус: ПРОВАЛ\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}