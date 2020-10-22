package com.horizen.schnorrnative;

import com.horizen.librustsidechains.FieldElement;
import org.junit.Test;

import java.util.Arrays;

import static org.junit.Assert.*;

public class SchnorrKeyPairTest {

    @Test
    public void testGenerate() throws Exception {

        try(SchnorrKeyPair keyPair = SchnorrKeyPair.generate())
        {
            assertNotNull("Key pair generation was unsuccessful.", keyPair);
            assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());
        }
    }

    @Test
    public void testSignVerify() throws Exception {

        byte[] skBytes = {
            33, 52, -46, -50, -26, -102, 64, 31, -36, 90, 100, 49, -69, 79, -83, -53, 61, -35, -88, -48, -122, -120, 15,
            -117, -124, 83, 7, 4, 20, -46, -56, -68, -58, -16, -82, 51, -9, -59, -17, -97, -110, -55, 84, 114, -12, -32,
            36, 28, -80, 98, 20, 68, -62, 23, -18, -22, 25, 92, 82, 13, 127, 77, -16, 123, -31, -125, 79, 103, -3, 21,
            -26, -31, 47, -103, 111, -86, -68, 39, 96, -124, -109, -64, -80, -116, -75, 90, 96, -118, 33, -39, -94, -28,
            121, 0, 1, 0
        };

        byte[] messageBytes = {
            99, 122, 4, 23, 113, 104, 61, 96, -63, 47, -51, -49, 88, -5, 42, 92, 32, 99, 58, 52, 83, 54, -96, -88, -99,
            56, -25, -98, 119, -39, 71, 118, 85, 109, 69, 74, 3, 45, -38, -103, -36, 70, 28, 110, -64, 90, 18, -107,
            -80, -49, 46, 4, -86, 46, -23, -46, -81, 113, -89, 126, 51, -104, -113, 46, 77, -18, -75, -6, 22, -52, 122,
            -53, 100, 113, -86, -33, -121, 51, 65, -24, 27, -28, -69, 4, -97, -27, 72, -106, -118, 64, 87, 25, -83, -19,
            0, 0,
        };

        byte[] sigBytes = {
            -23, 15, -85, -115, -31, 70, 62, -23, -28, 32, 60, -90, 44, -89, -6, -37, 110, 119, 6, 10, 105, 27, 87, -75,
            -82, 105, 29, 75, 126, -62, -57, -26, 21, 22, 98, -106, 19, 58, 15, -12, -6, 123, -125, -41, -4, 82, -102,
            -33, 100, -57, 92, -23, 114, -118, 83, -52, -8, 79, 11, 10, 24, 83, -74, 125, -27, -114, -29, -31, 82, -85,
            126, 117, 79, -68, 49, 79, 18, -50, 31, -28, -99, 75, -74, 108, -6, 0, 17, 0, 32, -83, 112, 35, -51, -71, 0,
            0, -65, -74, -110, 117, 23, -70, -105, -13, 35, -75, -118, 67, 23, 126, 40, -89, -21, 53, -63, 79, -41, -8,
            -98, 62, -41, -12, 123, 79, 94, 61, 87, 122, -101, -47, 119, 86, 36, -57, -100, 101, 77, -92, 55, -41, -26,
            77, -29, 5, 46, -62, -122, 110, 83, -19, -58, -37, 13, 96, 64, 46, 56, 20, 69, 12, -95, -113, -123, 118, 93,
            -22, 13, -91, 117, -100, -22, -103, -81, -118, -33, -76, -18, -100, -119, 11, -37, 12, -46, 28, -43, -105,
            66, -117, -100, 39, 0, 0
        };

        try
        (
            SchnorrSecretKey sk = SchnorrSecretKey.deserialize(skBytes);
            SchnorrKeyPair keyPair = new SchnorrKeyPair(sk);
            FieldElement message = FieldElement.deserialize(messageBytes);
            SchnorrSignature sig = SchnorrSignature.deserialize(sigBytes)
        )
        {
            assertNotNull("sk deserialization must not fail", sk);
            assertNotNull("message deserialization must not fail", message);
            assertNotNull("signature deserialization must not fail", sig);
            assertTrue("Schnorr signature must be valid", sig.isValidSignature());
            assertTrue("Signature must be verified", keyPair.getPublicKey().verifySignature(sig, message));
        }

    }

    @Test
    public void testRandomSignVerify() throws Exception {

        int samples = 100;

        for (int i = 0; i < samples; i++) {
            try
            (
                SchnorrKeyPair keyPair = SchnorrKeyPair.generate();
                FieldElement fieldElement = FieldElement.createRandom();
                FieldElement wrongFieldElement = FieldElement.createRandom()
            )
            {
                assertNotNull("Key pair generation was unsuccessful.", keyPair);
                assertTrue("Public key verification failed.", keyPair.getPublicKey().verifyKey());

                try(SchnorrSignature signature = keyPair.signMessage(fieldElement))
                {
                    assertNotNull("Attempt to sign message failed.", signature);
                    assertTrue("Schnorr signature must be valid", signature.isValidSignature());
                    assertTrue("Signature must be verified", keyPair.getPublicKey().verifySignature(signature, fieldElement));
                    assertFalse("Signature must not be verified", keyPair.getPublicKey().verifySignature(signature, wrongFieldElement));
                }
            }
        }
    }
}
