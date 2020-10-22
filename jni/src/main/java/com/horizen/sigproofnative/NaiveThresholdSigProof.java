package com.horizen.sigproofnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;

import java.util.List;

public class NaiveThresholdSigProof {

    private static native FieldElement nativeGetConstant(SchnorrPublicKey[] schnorrPublicKeys, long threshold);

    public static FieldElement getConstant(List<SchnorrPublicKey> schnorrPublicKeys, long threshold) {
        return nativeGetConstant(schnorrPublicKeys.toArray(new SchnorrPublicKey[0]), threshold);
    }

    private static native FieldElement nativeCreateMsgToSign(BackwardTransfer[] bt,
                                                             byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash);

    public static FieldElement createMsgToSign(BackwardTransfer[] bt,
                                               byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash) {
        return nativeCreateMsgToSign(bt, endEpochBlockHash, prevEndEpochBlockHash);
    }

    private static native CreateProofResult nativeCreateProof(BackwardTransfer[] bt,
                                                   byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                                   SchnorrSignature[] schnorrSignatures, SchnorrPublicKey[] schnorrPublicKeys,
                                                   long threshold, String provingKeyPath, boolean checkProvingKey);

    public static CreateProofResult createProof(List<BackwardTransfer> btList,
                                     byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                     List<SchnorrSignature> schnorrSignatureList, List<SchnorrPublicKey> schnorrPublicKeyList,
                                     long threshold, String provingKeyPath, boolean checkProvingKey) {
        return nativeCreateProof(btList.toArray(new BackwardTransfer[0]), endEpochBlockHash, prevEndEpochBlockHash,
                schnorrSignatureList.toArray(new SchnorrSignature[0]), schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, provingKeyPath, checkProvingKey);
    }

    public static CreateProofResult createProof(List<BackwardTransfer> btList,
                                                byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                                List<SchnorrSignature> schnorrSignatureList, List<SchnorrPublicKey> schnorrPublicKeyList,
                                                long threshold, String provingKeyPath) {
        return nativeCreateProof(btList.toArray(new BackwardTransfer[0]), endEpochBlockHash, prevEndEpochBlockHash,
                schnorrSignatureList.toArray(new SchnorrSignature[0]), schnorrPublicKeyList.toArray(new SchnorrPublicKey[0]),
                threshold, provingKeyPath, false); //Expensive check, disabled by default
    }

    private static native boolean nativeVerifyProof(BackwardTransfer[] btList,
                                      byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                      FieldElement constant, long quality, byte[] proof, boolean checkProof,
                                      String verificationKeyPath, boolean checkVerificationKey);

    public static boolean verifyProof(List<BackwardTransfer> btList,
                                      byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                      FieldElement constant, long quality, byte[] proof, boolean checkProof,
                                      String verificationKeyPath, boolean checkVerificationKey){
        return nativeVerifyProof(
                btList.toArray(new BackwardTransfer[0]),
                endEpochBlockHash, prevEndEpochBlockHash,
                constant, quality, proof, checkProof, verificationKeyPath, checkVerificationKey);
    }

    public static boolean verifyProof(List<BackwardTransfer> btList,
                                      byte[] endEpochBlockHash, byte[] prevEndEpochBlockHash,
                                      FieldElement constant, long quality, byte[] proof,
                                      String verificationKeyPath){
        return nativeVerifyProof(
                btList.toArray(new BackwardTransfer[0]),
                endEpochBlockHash, prevEndEpochBlockHash,
                constant, quality, proof, true, verificationKeyPath, true);
    }
}
