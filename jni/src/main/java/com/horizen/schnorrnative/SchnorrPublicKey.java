package com.horizen.schnorrnative;

import com.horizen.librustsidechains.*;

public class SchnorrPublicKey implements AutoCloseable
{

  public static final int PUBLIC_KEY_LENGTH = 97;

  private long publicKeyPointer;

  static {
    Library.load();
  }

  private SchnorrPublicKey(long publicKeyPointer) {
    if (publicKeyPointer == 0)
      throw new IllegalArgumentException("Public key pointer must be not null.");
    this.publicKeyPointer = publicKeyPointer;
  }

  private static native int nativeGetPublicKeySize();

  private static native SchnorrPublicKey nativeDeserializePublicKey(byte[] publicKeyBytes, boolean checkPublicKey);

  public static SchnorrPublicKey deserialize(byte[] publicKeyBytes, boolean checkPublicKey) {
    if (publicKeyBytes.length != PUBLIC_KEY_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect public key length, %d expected, %d found", PUBLIC_KEY_LENGTH, publicKeyBytes.length));

    return nativeDeserializePublicKey(publicKeyBytes, checkPublicKey);
  }

  public static SchnorrPublicKey deserialize(byte[] publicKeyBytes) {
    return SchnorrPublicKey.deserialize(publicKeyBytes, true);
  }

  private native byte[] nativeSerializePublicKey();

  public byte[] serializePublicKey() {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeSerializePublicKey();
  }

  private native void nativeFreePublicKey();

  public void freePublicKey() {
    if (publicKeyPointer != 0) {
      nativeFreePublicKey();
      publicKeyPointer = 0;
    }
  }

  private native boolean nativeVerifySignature(SchnorrSignature signature, FieldElement message); // jni call to Rust impl

  private native boolean nativeVerifyKey(); // jni call to Rust impl

  public boolean verifySignature(SchnorrSignature signature, FieldElement message) {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeVerifySignature(signature, message);
  }

  public boolean verifyKey() {
    if (publicKeyPointer == 0)
      throw new IllegalStateException("Public key was freed.");

    return nativeVerifyKey();
  }

  @Override
  public void close() throws Exception {
    freePublicKey();
  }
}

