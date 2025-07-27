package com.example.securetoken;

import java.io.Serializable;

public class SignedToken implements Serializable {
    private static final long serialVersionUID = 1L;

    private final byte[] data;
    private final byte[] signature;

    public SignedToken(byte[] data, byte[] signature) {
        this.data = data;
        this.signature = signature;
    }

    public byte[] getData() {
        return data;
    }

    public byte[] getSignature() {
        return signature;
    }
}