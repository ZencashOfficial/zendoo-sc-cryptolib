package com.horizen.vrfnative;

import com.horizen.librustsidechains.FieldElement;
import com.horizen.schnorrnative.SchnorrKeyPair;
import com.horizen.schnorrnative.SchnorrSignature;
import org.junit.Test;

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class VRFKeyPairTest {


    @Test
    public void testGenerate() throws Exception {

        try(VRFKeyPair keyPair = VRFKeyPair.generate())
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);

            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
        }
    }

    @Test
    public void testProveVerify() throws Exception {

        byte[] skBytes = {
            55, -30, 33, 71, -114, -74, 105, 126, -61, -19, 7, 118, -13, 108, 23, -51, -92, 69, -60, -65, 62, -58, -29,
            48, 116, -107, -55, 51, 86, 102, -100, 76, 36, -40, -91, 23, -85, 124, -125, 77, 19, 29, 125, -17, -87, -5,
            118, 63, 26, -17, 66, 111, 111, -120, -119, 40, -29, -33, 53, 55, -123, -107, 20, -111, 48, 50, -46, -65,
            113, -61, 8, -6, -29, -80, -121, -60, 54, -14, -110, -104, 59, 100, -1, -27, 77, 71, 60, -32, -122, 1, 39,
            -50, -96, 29, 0, 0
        };

        byte[] messageBytes = {
            -2, 99, 94, 19, 56, 121, 107, 88, 17, -102, 17, -95, 80, 104, 126, 125, -27, 66, -43, 122, 39, -124, 95,
            115, 100, 122, 80, -44, -31, 38, -78, -27, 40, -55, 11, -39, -11, -16, -59, -17, 100, 26, 54, 8, -99, -99,
            -92, -53, -121, 24, 71, 106, 89, -64, -116, -48, 37, -54, -85, -74, -83, -30, 81, 112, -54, 103, -125, 119,
            -102, -128, 19, 67, -18, -101, 92, 21, -120, -37, -67, 69, 14, -112, -78, 23, 94, 56, -82, 120, -2, -122,
            57, -120, 37, 119, 1, 0
        };

        byte[] proofBytes = {
            61, 100, 69, 22, -85, 79, -64, 99, -98, -99, -62, -128, 54, -14, -122, 102, -59, 109, 65, -64, 75, 37, -81,
            -40, 8, -108, -77, -112, -2, 122, 20, -20, -50, -91, -26, -54, -116, 61, -14, 99, -13, -80, -111, 23, 65,
            36, -94, -41, -87, -58, 109, -110, -113, -8, -93, 59, -71, -35, -28, -25, -66, -14, -23, -30, 126, 8, -1,
            -97, -113, 66, -65, -117, -127, 0, 75, 104, 81, -38, 94, 49, 11, 124, -102, -47, 8, -103, 81, -47, -89,
            -111, 15, -52, 41, 100, 0, 0, -111, 15, 71, 89, -105, 30, 12, -113, -126, 8, -54, -36, 41, 45, 33, 109, -55,
            -49, -20, 62, 24, -28, 45, -12, -116, 110, 17, 103, 118, 58, 29, -15, -19, -102, 100, -52, -119, -114, -47,
            15, -50, -124, -29, 71, 79, -120, -12, -48, -79, -117, -56, -6, -69, -98, -31, 82, 63, -123, 89, -126, -69,
            -21, -53, -10, 108, 72, -87, 121, -40, 45, -126, 104, -95, 117, -45, 29, -40, -58, -83, -5, 127, 108, -18,
            -95, 75, -88, -40, 116, -13, 78, 28, -6, -92, -63, 1, 0, 0, -120, -87, 92, -58, 73, -66, 17, 4, 76, -91, 27,
            24, -51, -15, -20, -128, -8, -67, 54, -76, 22, 58, -28, 19, 29, 121, -95, 11, -80, 25, 112, -104, -37, 47,
            18, -104, 43, -69, -85, 65, 21, -67, -63, 37, 65, -65, -30, 95, -1, -30, -46, 47, -48, 122, -102, -124, 52,
            95, -25, 122, 30, 21, 113, -41, 99, -74, -60, 107, -120, -63, -16, -54, -115, 64, -17, 32, 15, 84, 117, -62,
            -116, 111, 62, -13, 86, 66, 15, 27, -86, -42, 29, -127, 60, -69, 0, 0, -21, 63, -49, 85, 115, -99, 49, -55,
            37, 114, 29, 19, 64, -71, 4, 46, -111, 108, -121, -32, -127, 49, -47, 33, 119, 108, -109, 90, 60, -5, 118,
            1, -28, 87, 107, 63, 96, 16, 113, 110, -61, 66, -3, -126, -75, -80, 122, 97, -98, 49, -94, -11, -32, -13,
            88, -12, -127, -52, -33, -63, -112, 8, 64, 58, 49, -4, 86, -76, 40, 56, 28, 120, 92, 14, -112, -53, 8, 31,
            -41, -77, -73, -80, 50, -62, 99, 94, -67, 15, -110, 26, -41, 27, -126, 123, 0, 0
        };

        byte[] vrfOutputBytes = {
            -126, 18, -112, -103, 101, 88, -117, -21, 7, -72, -74, -128, -128, -99, -107, 31, -48, -44, 44, 38, 121, 28,
            -33, -88, -74, -68, 66, 26, -100, 115, -95, -98, -50, -57, -112, -81, 16, -72, -118, -58, -74, 65, 90, -96,
            -75, -56, -4, 44, 104, 44, 85, -99, -31, -99, 31, 11, -78, 118, -108, 96, -30, 55, 56, 30, -45, -109, -48,
            -9, 101, 30, -95, -15, -52, -72, -53, -97, -22, 120, 115, -54, 97, 16, -30, -54, 3, -11, 36, -97, -70, -46,
            42, -43, 11, 104, 1, 0
        };

        try
        (
            VRFSecretKey sk = VRFSecretKey.deserialize(skBytes);
            VRFKeyPair keyPair = new VRFKeyPair(sk);
            FieldElement message = FieldElement.deserialize(messageBytes);
            VRFProof proof = VRFProof.deserialize(proofBytes);
            FieldElement expectedVrfOutput = FieldElement.deserialize(vrfOutputBytes)
        )
        {
            assertNotNull("sk deserialization must not fail", sk);
            assertNotNull("message deserialization must not fail", message);
            assertNotNull("proof deserialization must not fail", proof);
            assertTrue("VRF Proof must be valid", proof.isValidVRFProof());
            assertNotNull("expectedVrfOutput deserialization must not fail", sk);

            try(FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proof, message))
            {
                assertNotNull("VRF Proof verification and VRF Output computation has failed.", vrfOutput);

                // Check vrfOutput == expectedVrfOutput
                assertEquals("vrfOutput and expectedVrfOutput must be equal", vrfOutput, expectedVrfOutput);
            }
        }
    }

    @Test
    public void testRandomProveVerify() throws Exception {
        int samples = 100;

        for(int i = 0; i < samples; i++) {
            try
            (
                VRFKeyPair keyPair = VRFKeyPair.generate();
                FieldElement fieldElement = FieldElement.createRandom();
                FieldElement wrongFieldElement = FieldElement.createRandom()
            )
            {
                assertNotNull("Key pair generation was unsuccessful.", keyPair);
                assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

                try
                (
                    VRFProveResult proofVRFOutputPair = keyPair.prove(fieldElement);
                    FieldElement vrfOutput = keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), fieldElement)
                )
                {
                    assertNotNull("Attempt to create vrf proof and output failed.", proofVRFOutputPair);
                    assertTrue("VRF Proof must be valid", proofVRFOutputPair.getVRFProof().isValidVRFProof());
                    assertNotNull("VRF Proof verification and VRF Output computation must not fail.", vrfOutput);
                    assertEquals("prove() and proof_to_hash() vrf outputs must be equal", proofVRFOutputPair.getVRFOutput(), vrfOutput);
                    assertNull("VRF Proof verification must fail", keyPair.getPublicKey().proofToHash(proofVRFOutputPair.getVRFProof(), wrongFieldElement));
                }
            }
        }
    }
}
