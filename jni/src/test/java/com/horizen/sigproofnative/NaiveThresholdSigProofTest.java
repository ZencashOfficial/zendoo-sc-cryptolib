package com.horizen.sigproofnative;

import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrPublicKey;
import com.horizen.schnorrnative.SchnorrSignature;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class NaiveThresholdSigProofTest {

    static int keyCount = 3;
    static int threshold = 2;

    static int backwardTransferCout = 5;

    List<SchnorrKeyPair> originalList = new ArrayList<>();
    List<SchnorrKeyPair> workingList = new ArrayList<>();

    List<BackwardTransfer> btList = new ArrayList<>();

    @Before
    public void testGenerate() {

        for (int i = 0; i<keyCount; i++) {
            SchnorrKeyPair keyPair = SchnorrKeyPair.generate();

            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

            originalList.add(keyPair);
            if (i < threshold)
                workingList.add(keyPair);
            else
            {
                SchnorrKeyPair kp = new SchnorrKeyPair(keyPair.getPublicKey());
                workingList.add(kp);
            }
        }

    }

    @Test
    public void testCreateProof() {

        byte[] endEpochBlockHash = new byte[32];
        byte[] prevEndEpochBlockHash = new byte[32];

        for(int i = 0; i < backwardTransferCout; i++) {

            byte[] publicKeyHash = new byte[32];
            long amount = i;

            btList.add(new BackwardTransfer(publicKeyHash, amount));
        }

        byte[] signature = NaiveThresholdSigProof.createProof(btList, endEpochBlockHash, prevEndEpochBlockHash, workingList, threshold, "");
    }
}
