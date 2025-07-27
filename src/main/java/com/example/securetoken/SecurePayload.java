package com.example.securetoken;


import java.io.Serializable;

// Этот класс будет передаваться по сети. Он содержит все необходимое.
public class SecurePayload implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] encryptedSessionKey; // Ключ AES, зашифрованный RSA
    private final byte[] initializationVector; // Вектор инициализации для AES
    private final byte[] encryptedData;       // Данные, зашифрованные AES

    public SecurePayload(byte[] encryptedSessionKey, byte[] initializationVector, byte[] encryptedData) {
        this.encryptedSessionKey = encryptedSessionKey;
        this.initializationVector = initializationVector;
        this.encryptedData = encryptedData;
    }

    public byte[] getEncryptedSessionKey() {
        return encryptedSessionKey;
    }

    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public byte[] getEncryptedData() {
        return encryptedData;
    }
}