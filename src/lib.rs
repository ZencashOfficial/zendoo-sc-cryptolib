extern crate jni;

use algebra::bytes::{FromBytes, FromBytesChecked, ToBytes};

use std::{ptr::null_mut, any::type_name};

use std::panic;

mod ginger_calls;
use ginger_calls::*;


fn read_raw_pointer<'a, T>(input: *const T) -> &'a T {
    assert!(!input.is_null());
    unsafe { &*input }
}

fn read_mut_raw_pointer<'a, T>(input: *mut T) -> &'a mut T {
    assert!(!input.is_null());
    unsafe { &mut *input }
}

fn read_nullable_raw_pointer<'a, T>(input: *const T) -> Option<&'a T> {
    unsafe { input.as_ref() }
}

fn deserialize_to_raw_pointer<T: FromBytes>(buffer: &[u8]) -> *mut T {
    match deserialize_from_buffer(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => return null_mut(),
    }
}

fn deserialize_to_raw_pointer_checked<T: FromBytesChecked>(buffer: &[u8]) -> *mut T {
    match deserialize_from_buffer_checked(buffer) {
        Ok(t) => Box::into_raw(Box::new(t)),
        Err(_) => return null_mut(),
    }
}

fn serialize_from_raw_pointer<T: ToBytes>(
    to_write: *const T,
    buffer: &mut [u8],
) {
    serialize_to_buffer(read_raw_pointer(to_write), buffer)
        .expect(format!("unable to write {} to buffer", type_name::<T>()).as_str())
}

use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject, JValue};
use jni::sys::{jbyteArray, jboolean, jint, jlong, jlongArray, jobject, jobjectArray};
use jni::sys::{JNI_TRUE, JNI_FALSE};

//Field element related functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeGetFieldElementSize(
    _env: JNIEnv,
    _field_element_class: JClass,
) -> jint { FIELD_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeSerializeFieldElement(
    _env: JNIEnv,
    _field_element: JObject,
) -> jbyteArray
{
    let fe_pointer = _env.get_field(_field_element, "fieldElementPointer", "J")
        .expect("Cannot get field element pointer.");

    let fe = read_raw_pointer({fe_pointer.j().unwrap() as *const FieldElement});

    let mut fe_bytes = [0u8; FIELD_SIZE];
    serialize_from_raw_pointer(fe, &mut fe_bytes[..]);

    _env.byte_array_from_slice(fe_bytes.as_ref())
        .expect("Cannot write field element.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeDeserializeFieldElement(
    _env: JNIEnv,
    _class: JClass,
    _field_element_bytes: jbyteArray,
) -> jobject
{
    let fe_bytes = _env.convert_byte_array(_field_element_bytes)
        .expect("Should be able to convert to Rust byte array");

    let fe_ptr: *const FieldElement = deserialize_to_raw_pointer(fe_bytes.as_slice());

    let fe: jlong = jlong::from(fe_ptr as i64);

    let fe_class = _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    let fe_object = _env.new_object(fe_class, "(J)V",
                                            &[JValue::Long(fe)])
        .expect("Cannot create FieldElement object.");

    *fe_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeCreateRandom(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _seed: jlong,
) -> jobject
{
    //Create random field element
    let fe = get_random_field_element(_seed as u64);

    //Return field element
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(fe)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeCreateFromLong(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _long: jlong
) -> jobject
{
    //Create field element from _long
    let fe = read_field_element_from_u64(_long as u64);

    //Return field element
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(fe)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeFreeFieldElement(
    _env: JNIEnv,
    _class: JClass,
    _fe: *mut FieldElement,
)
{
    if _fe.is_null()  { return }
    drop(unsafe { Box::from_raw(_fe) });
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_librustsidechains_FieldElement_nativeEquals(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _field_element_1: JObject,
    _field_element_2: JObject,
) -> jboolean
{
    //Read field_1
    let field_1 = {

        let f =_env.get_field(_field_element_1, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer_1");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    //Read field_2
    let field_2 = {

        let f =_env.get_field(_field_element_2, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer_2");

        read_raw_pointer(f.j().unwrap() as *const FieldElement)
    };

    match field_1 == field_2 {
        true => JNI_TRUE,
        false => JNI_FALSE,
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeGetPoseidonHash(
    _env: JNIEnv,
    _class: JClass,
    _personalization: jobjectArray,
) -> jobject
{
    //Read _personalization as array of FieldElement
    let personalization_len = _env.get_array_length(_personalization)
        .expect("Should be able to read personalization array size");
    let mut personalization = vec![];

    // Array can be empty
    for i in 0..personalization_len {
        let field_obj = _env.get_object_array_element(_personalization, i)
            .expect(format!("Should be able to read elem {} of the personalization array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        personalization.push(*field);
    }

    //Instantiate PoseidonHash
    let h = get_poseidon_hash(
        if personalization.is_empty() { None } else { Some(personalization.as_slice()) }
    );

    //Return PoseidonHash instance
    let h_ptr: jlong = jlong::from(Box::into_raw(Box::new(h)) as i64);

    let h_class =  _env.find_class("com/horizen/poseidonnative/PoseidonHash")
        .expect("Should be able to find PoseidonHash class");

    let result = _env.new_object(h_class, "(J)V", &[
        JValue::Long(h_ptr)]).expect("Should be able to create new long for PoseidonHash");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeUpdate(
    _env: JNIEnv,
    _h: JObject,
    _input: JObject,
){
    //Read PoseidonHash instance
    let digest = {

        let h = _env.get_field(_h, "poseidonHashPointer", "J")
            .expect("Should be able to get field poseidonHashPointer");

        read_mut_raw_pointer(h.j().unwrap() as *mut FieldHash)
    };

    //Read input
    let input = {

        let i =_env.get_field(_input, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(i.j().unwrap() as *const FieldElement)
    };

    update_poseidon_hash(digest, input);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeFinalize(
    _env: JNIEnv,
    _h: JObject,
) -> jobject
{
    //Read PoseidonHash instance
    let digest = {

        let h = _env.get_field(_h, "poseidonHashPointer", "J")
            .expect("Should be able to get field poseidonHashPointer");

        read_raw_pointer(h.j().unwrap() as *const FieldHash)
    };

    //Get digest
    let output = finalize_poseidon_hash(digest);

    //Return output
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(output)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeReset(
    _env: JNIEnv,
    _h: JObject,
    _personalization: jobjectArray,
){
    //Read PoseidonHash instance
    let digest = {

        let h = _env.get_field(_h, "poseidonHashPointer", "J")
            .expect("Should be able to get field poseidonHashPointer");

        read_mut_raw_pointer(h.j().unwrap() as *mut FieldHash)
    };

    //Read _personalization as array of FieldElement
    let personalization_len = _env.get_array_length(_personalization)
        .expect("Should be able to read personalization array size");
    let mut personalization = vec![];

    // Array can be empty
    for i in 0..personalization_len {
        let field_obj = _env.get_object_array_element(_personalization, i)
            .expect(format!("Should be able to read elem {} of the personalization array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        personalization.push(*field);
    }

    let personalization = if personalization.is_empty() { None } else { Some(personalization.as_slice()) };

    reset_poseidon_hash(digest, personalization)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_poseidonnative_PoseidonHash_nativeFreePoseidonHash(
    _env: JNIEnv,
    _h: JObject,
)
{
    let h_pointer = _env.get_field(_h, "poseidonHashPointer", "J")
        .expect("Cannot get poseidonHashPointer");

    let h = h_pointer.j().unwrap() as *mut FieldHash;

    if h.is_null()  { return }
    drop(unsafe { Box::from_raw(h) });
}