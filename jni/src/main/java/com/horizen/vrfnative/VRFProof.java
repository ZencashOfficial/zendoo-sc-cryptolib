package com.horizen.vrfnative;

import com.horizen.librustsidechains.Library;

public class VRFProof implements AutoCloseable
{

  public static int PROOF_LENGTH = 193;

  private long proofPointer;

  static {
    Library.load();
  }

  private VRFProof(long proofPointer) {
    if (proofPointer == 0)
      throw new IllegalArgumentException("Proof pointer must be not null.");
    this.proofPointer = proofPointer;
  }

  private static native byte[] nativeSerializeProof(long proofPointer);

  private static native VRFProof nativeDeserializeProof(byte[] proofBytes, boolean checkVRFProof);

  private static native void nativefreeProof(long proofPointer);

  public static VRFProof deserialize(byte[] proofBytes, boolean checkVRFProof) {
    if (proofBytes.length != PROOF_LENGTH)
      throw new IllegalArgumentException(String.format("Incorrect proof length, %d expected, %d found", PROOF_LENGTH, proofBytes.length));

    return nativeDeserializeProof(proofBytes, checkVRFProof);
  }

  public static VRFProof deserialize(byte[] proofBytes) {
    return VRFProof.deserialize(proofBytes, true);
  }

  public byte[] serializeProof() {
    return nativeSerializeProof(this.proofPointer);
  }

  private native boolean nativeIsValidVRFProof(); // jni call to Rust impl

  public boolean isValidVRFProof() {
    if (proofPointer == 0)
      throw new IllegalStateException("VRF Proof was freed.");

    return nativeIsValidVRFProof();
  }

  public void freeProof() {
    if (proofPointer != 0) {
      nativefreeProof(this.proofPointer);
      proofPointer = 0;
    }
  }

  @Override
  public void close() throws Exception {
    freeProof();
  }
}

