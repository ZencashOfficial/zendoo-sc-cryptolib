package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFSecretKey implements AutoCloseable
{
    public static final int SECRET_KEY_LENGTH = 48;

    private long secretKeyPointer;

    static {
        Library.load();
    }

    private VRFSecretKey(long secretKeyPointer) {
        if (secretKeyPointer == 0)
            throw new IllegalArgumentException("Secret key pointer must be not null.");
        this.secretKeyPointer = secretKeyPointer;
    }

    private static native int nativeGetSecretKeySize();

    private static native VRFSecretKey nativeDeserializeSecretKey(byte[] secretKeyBytes);

    public static VRFSecretKey deserialize(byte[] secretKeyBytes) {
        if (secretKeyBytes.length != SECRET_KEY_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect secret key length, %d expected, %d found", SECRET_KEY_LENGTH, secretKeyBytes.length));

        return nativeDeserializeSecretKey(secretKeyBytes);
    }

    private native byte[] nativeSerializeSecretKey();

    public byte[] serializeSecretKey() {
        if (secretKeyPointer == 0)
            throw new IllegalStateException("Secret key was freed.");

        return nativeSerializeSecretKey();
    }

    private native void nativeFreeSecretKey();

    public void freeSecretKey() {
        if (secretKeyPointer != 0) {
            nativeFreeSecretKey();
            secretKeyPointer = 0;
        }
    }

    private native VRFPublicKey nativeGetPublicKey();

    public VRFPublicKey getPublicKey() {
        if (secretKeyPointer == 0)
            throw new IllegalStateException("Secret key was freed.");

        return nativeGetPublicKey();
    }

    @Override
    public void close() throws Exception {
        freeSecretKey();
    }
}
