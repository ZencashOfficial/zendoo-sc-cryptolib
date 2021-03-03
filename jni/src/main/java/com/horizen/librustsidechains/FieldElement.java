package com.horizen.librustsidechains;

import java.util.Random;

public class FieldElement implements AutoCloseable {

    public static int FIELD_ELEMENT_LENGTH = 48;

    private long fieldElementPointer;

    static {
        Library.load();
    }

    private FieldElement(long fieldElementPointer) {
        this.fieldElementPointer = fieldElementPointer;
    }

    private static native FieldElement nativeCreateFromLong(long value);

    public static FieldElement createFromLong(long value) {
        return nativeCreateFromLong(value);
    }

    private static native FieldElement nativeCreateRandom(long seed);

    /*  NOTE: This function relies on a non-cryptographically safe RNG, therefore it
     *  must be used ONLY for testing purposes
     */
    public static FieldElement createRandom(long seed) { return nativeCreateRandom(seed); }

    public static FieldElement createRandom() {
        long seed = new Random().nextLong();
        return nativeCreateRandom(seed);
    }

    private static native int nativeGetFieldElementSize();

    public static int getFieldElementSize() {return  nativeGetFieldElementSize();}

    private native byte[] nativeSerializeFieldElement();

    public byte[] serializeFieldElement() {
        if (fieldElementPointer == 0)
            throw new IllegalStateException("Field element was freed.");

        return nativeSerializeFieldElement();
    }

    private static native FieldElement nativeDeserializeFieldElement(byte[] fieldElementBytes);

    public static FieldElement deserialize(byte[] fieldElementBytes) {
        if (fieldElementBytes.length != FIELD_ELEMENT_LENGTH)
            throw new IllegalArgumentException(String.format("Incorrect field element length, %d expected, %d found",
                    FIELD_ELEMENT_LENGTH, fieldElementBytes.length));

        return nativeDeserializeFieldElement(fieldElementBytes);
    }

    private static native void nativeFreeFieldElement(long fieldElementPointer);

    public void freeFieldElement() {
        if (fieldElementPointer != 0) {
            nativeFreeFieldElement(this.fieldElementPointer);
            fieldElementPointer = 0;
        }
    }

    private native boolean nativeEquals(FieldElement fe);

    @Override
    public boolean equals(Object o) {

        if (o == this) {
            return true;
        }

        if (!(o instanceof FieldElement)) {
            return false;
        }

        return nativeEquals((FieldElement) o);
    }

    @Override
    public void close() throws Exception {
        freeFieldElement();
    }
}
