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

//Public Schnorr key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeGetPublicKeySize(
    _env: JNIEnv,
    _schnorr_public_key_class: JClass,
) -> jint { SCHNORR_PK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeSerializePublicKey(
    _env: JNIEnv,
    _schnorr_public_key: JObject,
) -> jbyteArray
{
    let public_key_pointer = _env.get_field(_schnorr_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = read_raw_pointer({public_key_pointer.j().unwrap() as *const SchnorrPk});

    let mut pk = [0u8; SCHNORR_PK_SIZE];
    serialize_from_raw_pointer(public_key, &mut pk[..]);

    _env.byte_array_from_slice(pk.as_ref())
        .expect("Cannot write public key.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeDeserializePublicKey(
    _env: JNIEnv,
    _schnorr_public_key_class: JClass,
    _public_key_bytes: jbyteArray,
    _check_public_key: jboolean,
) -> jobject
{
    let pk_bytes = _env.convert_byte_array(_public_key_bytes)
        .expect("Cannot read public key bytes.");

    let public_key_pointer: *const SchnorrPk = if _check_public_key == JNI_TRUE {
        deserialize_to_raw_pointer_checked(pk_bytes.as_slice())
    } else {
        deserialize_to_raw_pointer(pk_bytes.as_slice())
    };

    let public_key: jlong = jlong::from(public_key_pointer as i64);

    let public_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey")
        .expect("Cannot find SchnorrPublicKey class.");

    let public_key_object = _env.new_object(public_key_class, "(J)V",
                                            &[JValue::Long(public_key)])
        .expect("Cannot create public key object.");

    *public_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeFreePublicKey(
    _env: JNIEnv,
    _schnorr_public_key: JObject,
)
{
    let public_key_pointer = _env.get_field(_schnorr_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = public_key_pointer.j().unwrap() as *mut SchnorrPk;

    if public_key.is_null()  { return }
    drop(unsafe { Box::from_raw(public_key) });
}

//Secret Schnorr key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeGetSecretKeySize(
    _env: JNIEnv,
    _schnorr_secret_key_class: JClass,
) -> jint { SCHNORR_SK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeSerializeSecretKey(
    _env: JNIEnv,
    _schnorr_secret_key: JObject,
) -> jbyteArray
{
    let secret_key_pointer = _env.get_field(_schnorr_secret_key, "secretKeyPointer", "J")
        .expect("Cannot get secret key pointer.");

    let secret_key = read_raw_pointer({secret_key_pointer.j().unwrap() as *const SchnorrSk});

    let mut sk = [0u8; SCHNORR_SK_SIZE];
    serialize_from_raw_pointer(secret_key, &mut sk[..]);

    _env.byte_array_from_slice(sk.as_ref())
        .expect("Cannot write secret key.")
}

#[no_mangle]

pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _schnorr_secret_key_class: JClass,
    _secret_key_bytes: jbyteArray,
) -> jobject
{
    let sk_bytes = _env.convert_byte_array(_secret_key_bytes)
        .expect("Cannot read public key bytes.");
    let secret_key_pointer: *const SchnorrSk = deserialize_to_raw_pointer(sk_bytes.as_slice());

    let secret_key: jlong = jlong::from(secret_key_pointer as i64);

    let secret_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrSecretKey")
        .expect("Cannot find SchnorrSecretKey class.");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V",
                                            &[JValue::Long(secret_key)])
        .expect("Cannot create secret key object.");

    *secret_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeFreeSecretKey(
    _env: JNIEnv,
    _schnorr_secret_key: JObject,
)
{
    let secret_key_pointer = _env.get_field(_schnorr_secret_key, "secretKeyPointer", "J")
        .expect("Cannot get secret key pointer.");

    let secret_key = secret_key_pointer.j().unwrap() as *mut SchnorrSk;

    if secret_key.is_null()  { return }
    drop(unsafe { Box::from_raw(secret_key) });
}

//Public VRF key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeGetPublicKeySize(
    _env: JNIEnv,
    _vrf_public_key_class: JClass,
) -> jint { VRF_PK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeSerializePublicKey(
    _env: JNIEnv,
    _vrf_public_key: JObject,
) -> jbyteArray
{
    let public_key_pointer = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = read_raw_pointer({public_key_pointer.j().unwrap() as *const VRFPk});

    let mut pk = [0u8; VRF_PK_SIZE];
    serialize_from_raw_pointer(public_key, &mut pk[..]);

    _env.byte_array_from_slice(pk.as_ref())
        .expect("Cannot write public key.")

}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeDeserializePublicKey(
    _env: JNIEnv,
    _vrf_public_key_class: JClass,
    _public_key_bytes: jbyteArray,
    _check_public_key: jboolean,
) -> jobject
{
    let pk_bytes = _env.convert_byte_array(_public_key_bytes)
        .expect("Cannot read public key bytes.");

    let public_key_pointer: *const VRFPk = if _check_public_key == JNI_TRUE {
        deserialize_to_raw_pointer_checked(pk_bytes.as_slice())
    } else {
        deserialize_to_raw_pointer(pk_bytes.as_slice())
    };

    let public_key: jlong = jlong::from(public_key_pointer as i64);

    let public_key_class = _env.find_class("com/horizen/vrfnative/VRFPublicKey")
        .expect("Cannot find SchnorrPublicKey class.");

    let public_key_object = _env.new_object(public_key_class, "(J)V",
                                            &[JValue::Long(public_key)])
        .expect("Cannot create public key object.");

    *public_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeFreePublicKey(
    _env: JNIEnv,
    _vrf_public_key: JObject,
)
{
    let public_key_pointer = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
        .expect("Cannot get public key pointer.");

    let public_key = public_key_pointer.j().unwrap() as *mut SchnorrPk;

    if public_key.is_null()  { return }
    drop(unsafe { Box::from_raw(public_key) });
}

//Secret VRF key utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetSecretKeySize(
    _env: JNIEnv,
    _vrf_secret_key_class: JClass,
) -> jint { VRF_SK_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeSerializeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject,
) -> jbyteArray
{
    let secret_key_pointer = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to read field secretKeyPointer");

    let secret_key = read_raw_pointer({secret_key_pointer.j().unwrap() as *const VRFSk});

    let mut sk = [0u8; VRF_SK_SIZE];
    serialize_from_raw_pointer(secret_key, &mut sk[..]);

    _env.byte_array_from_slice(sk.as_ref())
        .expect("Cannot write secret key.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeDeserializeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key_class: JClass,
    _secret_key_bytes: jbyteArray,
) -> jobject
{
    let sk_bytes = _env.convert_byte_array(_secret_key_bytes)
        .expect("Cannot read public key bytes.");

    let secret_key_pointer: *mut SchnorrSk = deserialize_to_raw_pointer(sk_bytes.as_slice());

    let secret_key: jlong = jlong::from(secret_key_pointer as i64);

    let secret_key_class = _env.find_class("com/horizen/vrfnative/VRFSecretKey")
        .expect("Cannot find SchnorrSecretKey class.");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V",
                                            &[JValue::Long(secret_key)])
        .expect("Cannot create secret key object.");

    *secret_key_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeFreeSecretKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject,
)
{
    let secret_key_pointer = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Cannot get secret key pointer.");

    let secret_key = secret_key_pointer.j().unwrap() as *mut SchnorrSk;

    if secret_key.is_null()  { return }
    drop(unsafe { Box::from_raw(secret_key) });
}

//Schnorr signature utility functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeGetSignatureSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { SCHNORR_SIG_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeSerializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig: *const SchnorrSig,
) -> jbyteArray
{
    let mut sig = [0u8; SCHNORR_SIG_SIZE];
    serialize_from_raw_pointer(_sig, &mut sig[..], );

    _env.byte_array_from_slice(sig.as_ref())
        .expect("Should be able to convert to jbyteArray")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeDeserializeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig_bytes: jbyteArray,
    _check_sig: jboolean,
) -> jobject
{
    let sig_bytes = _env.convert_byte_array(_sig_bytes)
        .expect("Should be able to convert to Rust byte array");

    let sig_ptr: *const SchnorrSig = if _check_sig == JNI_TRUE {
        deserialize_to_raw_pointer(sig_bytes.as_slice())
    } else {
        deserialize_to_raw_pointer_checked(sig_bytes.as_slice())
    };

    let sig: jlong = jlong::from(sig_ptr as i64);

    let sig_class = _env.find_class("com/horizen/schnorrnative/SchnorrSignature")
        .expect("Cannot find SchnorrSignature class.");

    let sig_object = _env.new_object(sig_class, "(J)V",
                                            &[JValue::Long(sig)])
        .expect("Cannot create signature object.");

    *sig_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativeIsValidSignature(
    _env: JNIEnv,
    _sig: JObject,
) -> jboolean
{
    let sig = _env.get_field(_sig, "signaturePointer", "J")
        .expect("Should be able to get field signaturePointer").j().unwrap() as *const SchnorrSig;

    if is_valid(read_raw_pointer(sig)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSignature_nativefreeSignature(
    _env: JNIEnv,
    _class: JClass,
    _sig: *mut SchnorrSig,
)
{
    if _sig.is_null()  { return }
    drop(unsafe { Box::from_raw(_sig) });
}

//Schnorr signature functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeGenerate(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
) -> jobject
{
    let (pk, sk) = schnorr_generate_key();

    let secret_key: jlong = jlong::from(Box::into_raw(Box::new(sk)) as i64);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let secret_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrSecretKey")
        .expect("Should be able to find SchnorrSecretKey class");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V", &[
        JValue::Long(secret_key)])
        .expect("Should be able to create new SchnorrSecretKey object");

    let public_key_class = _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey")
        .expect("Should be able to find SchnorrPublicKey class");

    let public_key_object = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)])
        .expect("Should be able to create new SchnorrPublicKey object");

    let class = _env.find_class("com/horizen/schnorrnative/SchnorrKeyPair")
        .expect("Should be able to find SchnorrKeyPair class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/schnorrnative/SchnorrSecretKey;Lcom/horizen/schnorrnative/SchnorrPublicKey;)V",
        &[JValue::Object(secret_key_object), JValue::Object(public_key_object)]
    ).expect("Should be able to create new (SchnorrSecretKey, SchnorrPublicKey) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrKeyPair_nativeSignMessage(
    _env: JNIEnv,
    _schnorr_key_pair: JObject,
    _message: JObject,
) -> jobject {

    //Read sk
    let sk_object = _env.get_field(_schnorr_key_pair,
                                   "secretKey",
                                   "Lcom/horizen/schnorrnative/SchnorrSecretKey;"
    ).expect("Should be able to get field secretKey").l().unwrap();
    let secret_key = {

        let s =_env.get_field(sk_object, "secretKeyPointer", "J")
            .expect("Should be able to get field secretKeyPointer");

        read_raw_pointer(s.j().unwrap() as *const SchnorrSk)
    };

    //Read pk
    let pk_object = _env.get_field(_schnorr_key_pair,
                                   "publicKey",
                                   "Lcom/horizen/schnorrnative/SchnorrPublicKey;"
    ).expect("Should be able to get field publicKey").l().unwrap();

    let public_key = {

        let p = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const SchnorrPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Sign message and return opaque pointer to sig
    let signature = match schnorr_sign(message, secret_key, public_key) {
        Ok(sig) => Box::into_raw(Box::new(sig)),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    let sign_result: jlong = jlong::from(signature as i64);

    let class = _env.find_class("com/horizen/schnorrnative/SchnorrSignature")
        .expect("Should be able to find class SchnorrSignature");

    let result =  _env.new_object(class, "(J)V", &[
        JValue::Long(sign_result)])
        .expect("Should be able to create new long for Schnorr signature");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    _public_key: JObject,
) -> jboolean
{
    let pk = _env.get_field(_public_key, "publicKeyPointer", "J")
        .expect("Should be able to get field publicKeyPointer").j().unwrap() as *const SchnorrPk;

    if schnorr_verify_public_key(read_raw_pointer(pk)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrSecretKey_nativeGetPublicKey(
    _env: JNIEnv,
    _secret_key: JObject
) -> jobject {

    let sk = _env.get_field(_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to get field secretKeyPointer").j().unwrap() as *const SchnorrSk;

    let secret_key = read_raw_pointer(sk);

    let pk = schnorr_get_public_key(secret_key);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let public_key_class =  _env.find_class("com/horizen/schnorrnative/SchnorrPublicKey")
        .expect("Should be able to find SchnorrPublicKey class");

    let result = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)]).expect("Should be able to create new long for SchnorrPk");

    *result
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_schnorrnative_SchnorrPublicKey_nativeVerifySignature(
    _env: JNIEnv,
    _public_key: JObject,
    _signature: JObject,
    _message: JObject,
) -> jboolean {

    //Read pk
    let public_key = {

        let p = _env.get_field(_public_key, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const SchnorrPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Read sig
    let signature = {
        let sig = _env.get_field(_signature, "signaturePointer", "J")
            .expect("Should be able to get field signaturePointer");

        read_raw_pointer(sig.j().unwrap() as *const SchnorrSig)
    };

    //Verify sig
    match schnorr_verify_signature(message, public_key, signature) {
        Ok(result) => if result {
            JNI_TRUE
        } else {
            JNI_FALSE
        },
        Err(_) => JNI_FALSE //CRYPTO_ERROR
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

//Merkle tree functions

//////////// MERKLE PATH

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeVerify(
    _env: JNIEnv,
    _path: JObject,
    _height: jint,
    _leaf: JObject,
    _root: JObject,
) -> jboolean
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let root = {

        let fe =_env.get_field(_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    match verify_ginger_merkle_path(path, _height as usize, leaf, root) {
        Ok(result) => if result { JNI_TRUE } else { JNI_FALSE },
        Err(_) => JNI_FALSE // CRYPTO_ERROR
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeVerifyWithoutLengthCheck(
    _env: JNIEnv,
    _path: JObject,
    _leaf: JObject,
    _root: JObject,
) -> jboolean
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let root = {

        let fe =_env.get_field(_root, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    match verify_ginger_merkle_path_without_length_check(path, leaf, root) {
        Ok(result) => if result { JNI_TRUE } else { JNI_FALSE },
        Err(_) => JNI_FALSE // CRYPTO_ERROR
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeApply(
    _env: JNIEnv,
    _path: JObject,
    _leaf: JObject,
) -> jobject
{
    let path = {
        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let root = apply(path, leaf);

    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(root)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeIsLeftmost(
    _env: JNIEnv,
    _path: JObject,
) -> jboolean
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    is_path_leftmost(path) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeIsRightmost(
    _env: JNIEnv,
    _path: JObject,
) -> jboolean
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    is_path_rightmost(path) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeIsNonEmptyRightmost(
    _env: JNIEnv,
    _path: JObject,
) -> jboolean
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    is_path_non_empty_rightmost(path) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeLeafIndex(
    _env: JNIEnv,
    _path: JObject,
) -> jlong
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    get_leaf_index_from_path(path) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeSerialize(
    _env: JNIEnv,
    _path: JObject,
) -> jbyteArray
{
    let path = {

        let t =_env.get_field(_path, "merklePathPointer", "J")
            .expect("Should be able to get field merklePathPointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHTPath)
    };

    let path_bytes_len = get_path_size_in_bytes(path);
    let mut path_bytes = vec![0u8; path_bytes_len];
    serialize_to_buffer(path, path_bytes.as_mut_slice())
        .expect("Unable to write Merkle Path to buffer");

    _env.byte_array_from_slice(path_bytes.as_ref())
        .expect("Cannot write Merkle Path to jbyteArray.")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeDeserialize(
    _env: JNIEnv,
    _class: JClass,
    _path_bytes: jbyteArray,
) -> jobject
{
    let path_bytes = _env.convert_byte_array(_path_bytes)
        .expect("Should be able to convert to Rust byte array");

    let path_ptr: *const GingerMHTPath = deserialize_to_raw_pointer(path_bytes.as_slice());

    let path: jlong = jlong::from(path_ptr as i64);

    let path_class = _env.find_class("com/horizen/merkletreenative/MerklePath")
        .expect("Cannot find MerklePath class.");

    let path_object = _env.new_object(path_class, "(J)V",
                                    &[JValue::Long(path)])
        .expect("Cannot create MerklePath object.");

    *path_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_MerklePath_nativeFreeMerklePath(
    _env: JNIEnv,
    _class: JClass,
    _path: *mut GingerMHTPath,
)
{
    if _path.is_null()  { return }
    drop(unsafe { Box::from_raw(_path) });
}

////////////RANDOM ACCESS MERKLE TREE
#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeInit(
    _env: JNIEnv,
    _class: JClass,
    _height: jint,
    _processing_step: jlong,
) -> jobject
{
    // Create new InMemoryOptimizedMerkleTree Rust side
    let mt = new_ginger_mht(
        _height as usize,
        _processing_step as usize
    );

    // Create and return new InMemoryOptimizedMerkleTree Java side

    let mt_ptr: jlong = jlong::from(Box::into_raw(Box::new(mt)) as i64);

    _env.new_object(_class, "(J)V", &[JValue::Long(mt_ptr)])
        .expect("Should be able to create new InMemoryOptimizedMerkleTree object")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeAppend(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
)
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerMHT)
    };

    append_leaf_to_ginger_mht(tree, leaf);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeFinalize(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHT)
    };

    let tree_copy = finalize_ginger_mht(tree);

    let tree_copy_ptr: jlong = jlong::from(Box::into_raw(Box::new(tree_copy)) as i64);

    let tree_class = _env.find_class("com/horizen/merkletreenative/InMemoryOptimizedMerkleTree")
        .expect("Cannot find InMemoryOptimizedMerkleTree class.");

    _env.new_object(tree_class, "(J)V", &[JValue::Long(tree_copy_ptr)])
        .expect("Cannot create InMemoryOptimizedMerkleTree object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeFinalizeInPlace(
    _env: JNIEnv,
    _tree: JObject,
)
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerMHT)
    };

    finalize_ginger_mht_in_place(tree);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeRoot(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHT)
    };

    let root = get_ginger_mht_root(tree)
        .expect("Tree must've been finalized");

    let root_ptr: jlong = jlong::from(Box::into_raw(Box::new(root)) as i64);

    let fe_class = _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    _env.new_object(fe_class, "(J)V", &[JValue::Long(root_ptr)])
        .expect("Cannot create FieldElement object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeGetMerklePath(
    _env: JNIEnv,
    _tree: JObject,
    _leaf_index: jlong,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerMHT)
    };

    let path = get_ginger_mht_path(tree, _leaf_index as u64)
        .expect("Tree must've been finalized");

    let path_ptr: jlong = jlong::from(Box::into_raw(Box::new(path)) as i64);

    let path_class = _env.find_class("com/horizen/merkletreenative/MerklePath")
        .expect("Cannot find MerklePath class.");

    _env.new_object(path_class, "(J)V", &[JValue::Long(path_ptr)])
        .expect("Cannot create MerklePath object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeReset(
    _env: JNIEnv,
    _tree: JObject,
)
{
    let tree = {

        let t =_env.get_field(_tree, "inMemoryOptimizedMerkleTreePointer", "J")
            .expect("Should be able to get field inMemoryOptimizedMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerMHT)
    };

    reset_ginger_mht(tree);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_InMemoryOptimizedMerkleTree_nativeFreeInMemoryOptimizedMerkleTree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut GingerMHT,
)
{
    if _tree.is_null()  { return }
    drop(unsafe { Box::from_raw(_tree) });
}

////////////SPARSE MERKLE TREE
#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeInit(
    _env: JNIEnv,
    _class: JClass,
    _height: jint,
    _db_path: JString,
) -> jobject
{
    // Read db_path
    let db_path = _env.get_string(_db_path)
        .expect("Should be able to read jstring as Rust String");

    // Create new BigMerkleTree Rust side
    let mt = get_ginger_smt(
        _height as usize,
        db_path.to_str().unwrap(),
    ).expect("Should be able to create new BigMerkleTree");

    // Create and return new BigMerkleTree Java side

    let mt_ptr: jlong = jlong::from(Box::into_raw(Box::new(mt)) as i64);

    _env.new_object(_class, "(J)V", &[JValue::Long(mt_ptr)])
        .expect("Should be able to create new BigMerkleTree object")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeGetPosition(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
) -> jlong
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerSMT)
    };

    get_position_in_ginger_smt(tree, leaf) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeGetAbsolutePosition(
    _env: JNIEnv,
    _class: JClass,
    _leaf: JObject,
    _height: jint,
) -> jlong
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    leaf_to_index(leaf, _height as usize) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeIsPositionEmpty(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong,
) -> jboolean
{
    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerSMT)
    };

    is_position_empty_in_ginger_smt(tree, _position as u64) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeAddLeaf(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
    _position: jlong,
)
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerSMT)
    };

    add_leaf_to_ginger_smt(tree, leaf, _position as u64);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeRemoveLeaf(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong,
)
{
    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerSMT)
    };

    remove_leaf_from_ginger_smt(tree, _position as u64);
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeRoot(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const GingerSMT)
    };

    let root = get_ginger_smt_root(tree);

    let root_ptr: jlong = jlong::from(Box::into_raw(Box::new(root)) as i64);

    let fe_class = _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    _env.new_object(fe_class, "(J)V", &[JValue::Long(root_ptr)])
        .expect("Cannot create FieldElement object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeGetMerklePath(
    _env: JNIEnv,
    _tree: JObject,
    _leaf_position: jlong,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerSMT)
    };

    let path = get_ginger_smt_path(tree, _leaf_position as u64);

    let path_ptr: jlong = jlong::from(Box::into_raw(Box::new(path)) as i64);

    let path_class = _env.find_class("com/horizen/merkletreenative/MerklePath")
        .expect("Cannot find MerklePath class.");

    _env.new_object(path_class, "(J)V", &[JValue::Long(path_ptr)])
        .expect("Cannot create MerklePath object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeFlush(
    _env: JNIEnv,
    _tree: JObject,
)
{
    let tree = {

        let t =_env.get_field(_tree, "merkleTreePointer", "J")
            .expect("Should be able to get field merkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut GingerSMT)
    };

    flush_ginger_smt(tree)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeFreeMerkleTree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut GingerSMT,
)
{
    if _tree.is_null()  { return }
    drop(unsafe { Box::from_raw(_tree) });
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigMerkleTree_nativeFreeAndDestroyMerkleTree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut GingerSMT,
)
{
    if _tree.is_null()  { return }

    let tree = read_mut_raw_pointer(_tree);
    set_ginger_smt_persistency(tree, false);

    drop(unsafe { Box::from_raw(_tree) });
}

////////////LAZY SPARSE MERKLE TREE
#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeInit(
    _env: JNIEnv,
    _class: JClass,
    _height: jint,
    _db_path: JString,
) -> jobject
{
    // Read db_path
    let db_path = _env.get_string(_db_path)
        .expect("Should be able to read jstring as Rust String");

    // Create new BigLazyMerkleTree Rust side
    let mt = get_lazy_ginger_smt(
        _height as usize,
        db_path.to_str().unwrap(),
    ).expect("Should be able to create new BigLazyMerkleTree");

    // Create and return new BigLazyMerkleTree Java side

    let mt_ptr: jlong = jlong::from(Box::into_raw(Box::new(mt)) as i64);

    _env.new_object(_class, "(J)V", &[JValue::Long(mt_ptr)])
        .expect("Should be able to create new BigLazyMerkleTree object")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeGetPosition(
    _env: JNIEnv,
    _tree: JObject,
    _leaf: JObject,
) -> jlong
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const LazyGingerSMT)
    };

    get_position_in_lazy_ginger_smt(tree, leaf) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeGetAbsolutePosition(
    _env: JNIEnv,
    _class: JClass,
    _leaf: JObject,
    _height: jint,
) -> jlong
{
    let leaf = {

        let fe =_env.get_field(_leaf, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(fe.j().unwrap() as *const FieldElement)
    };

    leaf_to_index(leaf, _height as usize) as jlong
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeIsPositionEmpty(
    _env: JNIEnv,
    _tree: JObject,
    _position: jlong,
) -> jboolean
{
    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const LazyGingerSMT)
    };

    is_position_empty_in_lazy_ginger_smt(tree, _position as u64) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeAddLeaves(
    _env: JNIEnv,
    _tree: JObject,
    _leaves: jobjectArray,
) -> jobject
{
    //Read _leaves as array of FieldElement
    let leaves_len = _env.get_array_length(_leaves)
        .expect("Should be able to read leaves array size");
    let mut leaves = vec![];

    for i in 0..leaves_len {
        let field_obj = _env.get_object_array_element(_leaves, i)
            .expect(format!("Should be able to read elem {} of the leaves array", i).as_str());

        let field = {

            let f =_env.get_field(field_obj, "fieldElementPointer", "J")
                .expect("Should be able to get field fieldElementPointer");

            read_raw_pointer(f.j().unwrap() as *const FieldElement)
        };

        leaves.push(*field);
    }

    // Read tree
    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut LazyGingerSMT)
    };

    // Update the tree with leaves and get the root
    let root = add_leaves_to_ginger_lazy_smt(tree, leaves.as_slice());

    // Return root as FieldElement object
    let root_ptr: jlong = jlong::from(Box::into_raw(Box::new(root)) as i64);

    let fe_class = _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    _env.new_object(fe_class, "(J)V", &[JValue::Long(root_ptr)])
        .expect("Cannot create FieldElement object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeRemoveLeaves(
    _env: JNIEnv,
    _tree: JObject,
    _positions: jlongArray,
) -> jobject
{
    //Read _positions as an array of jlongs
    let positions_len = _env.get_array_length(_positions)
        .expect("Should be able to read positions array size");

    let mut positions = vec![jlong::from(0i64); positions_len as usize];
    _env.get_long_array_region(_positions, 0, positions.as_mut_slice())
        .expect("Should be able to read _positions into a jlong slice");

    // Read tree
    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut LazyGingerSMT)
    };

    // Update the tree with leaves and get the root
    let root = remove_leaves_from_ginger_lazy_smt(
        tree,
        positions.as_slice(),
    );

    // Return root as FieldElement object
    let root_ptr: jlong = jlong::from(Box::into_raw(Box::new(root)) as i64);

    let fe_class = _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    _env.new_object(fe_class, "(J)V", &[JValue::Long(root_ptr)])
        .expect("Cannot create FieldElement object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeRoot(
    _env: JNIEnv,
    _tree: JObject,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_raw_pointer(t.j().unwrap() as *const LazyGingerSMT)
    };

    let root = get_lazy_ginger_smt_root(tree);

    let root_ptr: jlong = jlong::from(Box::into_raw(Box::new(root)) as i64);

    let fe_class = _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Cannot find FieldElement class.");

    _env.new_object(fe_class, "(J)V", &[JValue::Long(root_ptr)])
        .expect("Cannot create FieldElement object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeGetMerklePath(
    _env: JNIEnv,
    _tree: JObject,
    _leaf_position: jlong,
) -> jobject
{
    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut LazyGingerSMT)
    };

    let path = get_lazy_ginger_smt_path(tree, _leaf_position as u64);

    let path_ptr: jlong = jlong::from(Box::into_raw(Box::new(path)) as i64);

    let path_class = _env.find_class("com/horizen/merkletreenative/MerklePath")
        .expect("Cannot find MerklePath class.");

    _env.new_object(path_class, "(J)V", &[JValue::Long(path_ptr)])
        .expect("Cannot create MerklePath object.")
        .into_inner()
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeFlush(
    _env: JNIEnv,
    _tree: JObject,
)
{
    let tree = {

        let t =_env.get_field(_tree, "lazyMerkleTreePointer", "J")
            .expect("Should be able to get field lazyMerkleTreePointer");

        read_mut_raw_pointer(t.j().unwrap() as *mut LazyGingerSMT)
    };

    flush_lazy_ginger_smt(tree)
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeFreeLazyMerkleTree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut LazyGingerSMT,
)
{
    if _tree.is_null()  { return }
    drop(unsafe { Box::from_raw(_tree) });
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_merkletreenative_BigLazyMerkleTree_nativeFreeAndDestroyLazyMerkleTree(
    _env: JNIEnv,
    _class: JClass,
    _tree: *mut LazyGingerSMT,
)
{
    if _tree.is_null()  { return }

    let tree = read_mut_raw_pointer(_tree);
    set_ginger_lazy_smt_persistency(tree, false);

    drop(unsafe { Box::from_raw(_tree) });
}


//VRF utility functions

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeGetProofSize(
    _env: JNIEnv,
    _class: JClass,
) -> jint { VRF_PROOF_SIZE as jint }

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeSerializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof: *const VRFProof,
) -> jbyteArray
{
    let mut proof = [0u8; VRF_PROOF_SIZE];
    serialize_from_raw_pointer(_proof, &mut proof[..]);

    _env.byte_array_from_slice(proof.as_ref())
        .expect("Should be able to convert to jbyteArray")
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeDeserializeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof_bytes: jbyteArray,
    _check_proof: jboolean,
) -> jobject
{
    let proof_bytes = _env.convert_byte_array(_proof_bytes)
        .expect("Should be able to convert to Rust byte array");

    let proof_ptr: *const VRFProof = if _check_proof == JNI_TRUE {
        deserialize_to_raw_pointer_checked(proof_bytes.as_slice())
    } else {
        deserialize_to_raw_pointer(proof_bytes.as_slice())
    };

    let proof: jlong = jlong::from(proof_ptr as i64);

    let proof_class = _env.find_class("com/horizen/vrfnative/VRFProof")
        .expect("Cannot find VRFProof class.");

    let proof_object = _env.new_object(proof_class, "(J)V",
                                     &[JValue::Long(proof)])
        .expect("Cannot create vrf proof object.");

    *proof_object
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativeIsValidVRFProof(
    _env: JNIEnv,
    _vrf_proof: JObject,
) -> jboolean
{
    let proof = _env.get_field(_vrf_proof, "proofPointer", "J")
        .expect("Should be able to get field proofPointer").j().unwrap() as *const VRFProof;

    if is_valid(read_raw_pointer(proof)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFProof_nativefreeProof(
    _env: JNIEnv,
    _class: JClass,
    _proof: *mut VRFProof,
)
{
    if _proof.is_null()  { return }
    drop(unsafe { Box::from_raw(_proof) });
}


//VRF functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFKeyPair_nativeGenerate(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass
) -> jobject
{

    let (pk, sk) = vrf_generate_key();

    let secret_key: jlong = jlong::from(Box::into_raw(Box::new(sk)) as i64);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let secret_key_class = _env.find_class("com/horizen/vrfnative/VRFSecretKey")
        .expect("Should be able to find VRFSecretKey class");

    let secret_key_object = _env.new_object(secret_key_class, "(J)V", &[
        JValue::Long(secret_key)])
        .expect("Should be able to create new VRFSecretKey object");

    let public_key_class = _env.find_class("com/horizen/vrfnative/VRFPublicKey")
        .expect("Should be able to find VRFPublicKey class");

    let public_key_object = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)])
        .expect("Should be able to create new VRFPublicKey object");

    let class = _env.find_class("com/horizen/vrfnative/VRFKeyPair")
        .expect("Should be able to find VRFKeyPair class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/vrfnative/VRFSecretKey;Lcom/horizen/vrfnative/VRFPublicKey;)V",
        &[JValue::Object(secret_key_object), JValue::Object(public_key_object)]
    ).expect("Should be able to create new (VRFSecretKey, VRFPublicKey) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFKeyPair_nativeProve(
    _env: JNIEnv,
    _vrf_key_pair: JObject,
    _message: JObject
) -> jobject {

    //Read sk
    let sk_object = _env.get_field(_vrf_key_pair,
                                   "secretKey",
                                   "Lcom/horizen/vrfnative/VRFSecretKey;"
    ).expect("Should be able to get field vrfKey").l().unwrap();

    let secret_key = {

        let s =_env.get_field(sk_object, "secretKeyPointer", "J")
            .expect("Should be able to get field secretKeyPointer");

        read_raw_pointer(s.j().unwrap() as *const VRFSk)
    };

    //Read pk
    let pk_object = _env.get_field(_vrf_key_pair,
                                   "publicKey",
                                   "Lcom/horizen/vrfnative/VRFPublicKey;"
    ).expect("Should be able to get field publicKey").l().unwrap();

    let public_key = {

        let p = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Compute vrf proof
    let (proof, vrf_out) = match vrf_prove(message, secret_key, public_key) {
        Ok((p, vrf_out)) =>
            (Box::into_raw(Box::new(p)), Box::into_raw(Box::new(vrf_out))),
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Create VRFProof instance
    let proof_ptr: jlong = jlong::from(proof as i64);

    let proof_class = _env.find_class("com/horizen/vrfnative/VRFProof")
        .expect("Should be able to find class VRFProof");

    let proof_object =  _env.new_object(proof_class, "(J)V", &[
        JValue::Long(proof_ptr)])
        .expect("Should be able to create new long for VRF proof");

    //Create FieldElement instance
    let field_ptr: jlong = jlong::from(vrf_out as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let field_object = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    //Create and return VRFProveResult instance
    let class = _env.find_class("com/horizen/vrfnative/VRFProveResult")
        .expect("Should be able to find VRFProveResult class");

    let result = _env.new_object(
        class,
        "(Lcom/horizen/vrfnative/VRFProof;Lcom/horizen/librustsidechains/FieldElement;)V",
        &[JValue::Object(proof_object), JValue::Object(field_object)]
    ).expect("Should be able to create new VRFProveResult:(VRFProof, FieldElement) object");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFSecretKey_nativeGetPublicKey(
    _env: JNIEnv,
    _vrf_secret_key: JObject
) -> jobject {

    let sk = _env.get_field(_vrf_secret_key, "secretKeyPointer", "J")
        .expect("Should be able to get field secretKeyPointer").j().unwrap() as *const VRFSk;

    let secret_key = read_raw_pointer(sk);

    let pk = vrf_get_public_key(secret_key);
    let public_key: jlong = jlong::from(Box::into_raw(Box::new(pk)) as i64);

    let public_key_class =  _env.find_class("com/horizen/vrfnative/VRFPublicKey")
        .expect("Should be able to find VRFPublicKey class");

    let result = _env.new_object(public_key_class, "(J)V", &[
        JValue::Long(public_key)]).expect("Should be able to create new long for VRFPk");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeVerifyKey(
    _env: JNIEnv,
    _vrf_public_key: JObject,
) -> jboolean
{

    let pk = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
        .expect("Should be able to get field publicKeyPointer").j().unwrap() as *const VRFPk;

    if vrf_verify_public_key(read_raw_pointer(pk)) {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_vrfnative_VRFPublicKey_nativeProofToHash(
    _env: JNIEnv,
    _vrf_public_key: JObject,
    _proof: JObject,
    _message: JObject,
) -> jobject
{

    let public_key = {

        let p = _env.get_field(_vrf_public_key, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFPk)
    };

    //Read message
    let message = {

        let m =_env.get_field(_message, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(m.j().unwrap() as *const FieldElement)
    };

    //Read proof
    let proof = {
        let p = _env.get_field(_proof, "proofPointer", "J")
            .expect("Should be able to get field proofPointer");

        read_raw_pointer(p.j().unwrap() as *const VRFProof)
    };

    //Verify vrf proof and get vrf output
    let vrf_out = match vrf_proof_to_hash(message, public_key, proof) {
        Ok(result) => result,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Return vrf output
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(vrf_out)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

//Naive threshold signature proof functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeGetConstant(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _schnorr_pks_list: jobjectArray,
    _threshold: jlong,
) -> jobject
{
    //Extract Schnorr pks
    let mut pks = vec![];

    let pks_list_size = _env.get_array_length(_schnorr_pks_list)
        .expect("Should be able to get schnorr_pks_list size");

    for i in 0..pks_list_size {

        let pk_object = _env.get_object_array_element(_schnorr_pks_list, i)
            .expect(format!("Should be able to get elem {} of schnorr_pks_list", i).as_str());

        let pk = _env.get_field(pk_object, "publicKeyPointer", "J")
            .expect("Should be able to get field publicKeyPointer");

        pks.push(*read_raw_pointer(pk.j().unwrap() as *const SchnorrPk));
    }

    //Extract threshold
    let threshold = _threshold as u64;

    //Compute constant
    let constant = compute_pks_threshold_hash(pks.as_slice(), threshold);

    //Return constant
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(constant)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}


#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateMsgToSign(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _end_epoch_block_hash: jbyteArray,
    _prev_end_epoch_block_hash: jbyteArray,
) -> jobject
{
    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0
    {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());

            let pk: [u8; 20] = {
                let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                    .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

                let mut pk_bytes = [0u8; 20];

                _env.convert_byte_array(p)
                    .expect("Should be able to convert to Rust byte array")
                    .write(&mut pk_bytes[..])
                    .expect("Should be able to write into byte array of fixed size");

                pk_bytes
            };

            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push(BackwardTransfer::new(pk, a));
        }
    }

    //Extract block hashes
    let end_epoch_block_hash = {
        let t = _env.convert_byte_array(_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        read_field_element_from_buffer_with_padding(&end_epoch_block_hash_bytes)
            .expect("Should be able to read a FieldElement from a 32 byte array")

    };

    let prev_end_epoch_block_hash = {
        let t = _env.convert_byte_array(_prev_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut prev_end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut prev_end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        read_field_element_from_buffer_with_padding(&prev_end_epoch_block_hash_bytes)
            .expect("Should be able to read a FieldElement from a 32 byte array")
    };

    //Compute message to sign:
    let msg = match compute_msg_to_sign(
        &end_epoch_block_hash,
        &prev_end_epoch_block_hash,
        bt_list.as_slice()
    ){
        Ok((_, msg)) => msg,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR
    };

    //Return msg
    let field_ptr: jlong = jlong::from(Box::into_raw(Box::new(msg)) as i64);

    let field_class =  _env.find_class("com/horizen/librustsidechains/FieldElement")
        .expect("Should be able to find FieldElement class");

    let result = _env.new_object(field_class, "(J)V", &[
        JValue::Long(field_ptr)]).expect("Should be able to create new long for FieldElement");

    *result
}

#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeCreateProof(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _end_epoch_block_hash: jbyteArray,
    _prev_end_epoch_block_hash: jbyteArray,
    _schnorr_sigs_list: jobjectArray,
    _schnorr_pks_list:  jobjectArray,
    _threshold: jlong,
    _proving_key_path: JString,
    _check_proving_key: jboolean, //WARNING: Very expensive check
) -> jobject
{
    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());


            let pk: [u8; 20] = {
                let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                    .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

                let mut pk_bytes = [0u8; 20];

                _env.convert_byte_array(p)
                    .expect("Should be able to convert to Rust byte array")
                    .write(&mut pk_bytes[..])
                    .expect("Should be able to write into byte array of fixed size");

                pk_bytes
            };

            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push(BackwardTransfer::new(pk, a));
        }
    }

    //Extract Schnorr signatures and the corresponding Schnorr pks
    let mut sigs = vec![];
    let mut pks = vec![];

    let sigs_list_size = _env.get_array_length(_schnorr_sigs_list)
        .expect("Should be able to get schnorr_sigs_list size");

    let pks_list_size = _env.get_array_length(_schnorr_pks_list)
        .expect("Should be able to get schnorr_pks_list size");

    assert_eq!(sigs_list_size, pks_list_size);

    for i in 0..sigs_list_size {
        //Get i-th sig
        let sig_object = _env.get_object_array_element(_schnorr_sigs_list, i)
            .expect(format!("Should be able to get elem {} of schnorr_sigs_list", i).as_str());

        let pk_object = _env.get_object_array_element(_schnorr_pks_list, i)
            .expect(format!("Should be able to get elem {} of schnorr_pks_list", i).as_str());

        let signature = {
            let sig = _env.get_field(sig_object, "signaturePointer", "J")
                .expect("Should be able to get field signaturePointer");

            match read_nullable_raw_pointer(sig.j().unwrap() as *const SchnorrSig) {
                Some(sig) => Some(*sig),
                None => None,
            }
        };

        let public_key = {
            let pk = _env.get_field(pk_object, "publicKeyPointer", "J")
                .expect("Should be able to get field publicKeyPointer");

            read_raw_pointer(pk.j().unwrap() as *const SchnorrPk)
        };

        sigs.push(signature);
        pks.push(*public_key);
    }

    //Extract block hashes
    let end_epoch_block_hash = {
        let t = _env.convert_byte_array(_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        end_epoch_block_hash_bytes
    };

    let prev_end_epoch_block_hash = {
        let t = _env.convert_byte_array(_prev_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut prev_end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut prev_end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        prev_end_epoch_block_hash_bytes
    };

    //Extract threshold
    let threshold = _threshold as u64;

    //Extract params_path str
    let proving_key_path = _env.get_string(_proving_key_path)
        .expect("Should be able to read jstring as Rust String");

    //create proof
    let (proof, quality) = match create_naive_threshold_sig_proof(
        pks.as_slice(),
        sigs,
        &end_epoch_block_hash,
        &prev_end_epoch_block_hash,
        bt_list.as_slice(),
        threshold,
        proving_key_path.to_str().unwrap(),
        _check_proving_key == JNI_TRUE,
    ) {
        Ok(proof) => proof,
        Err(_) => return std::ptr::null::<jobject>() as jobject //CRYPTO_ERROR or IO_ERROR
    };

    //Serialize proof
    let mut proof_bytes = [0u8; ZK_PROOF_SIZE];
    proof.write(&mut proof_bytes[..])
        .expect("Should be able to write proof into proof_bytes");

    //Return proof serialized
    let proof_serialized = _env.byte_array_from_slice(proof_bytes.as_ref())
        .expect("Should be able to convert Rust slice into jbytearray");

    //Create new CreateProofResult object
    let proof_result_class = _env.find_class("com/horizen/sigproofnative/CreateProofResult")
        .expect("Should be able to find CreateProofResult class");

    let result = _env.new_object(
        proof_result_class,
        "([BJ)V",
        &[JValue::Object(JObject::from(proof_serialized)), JValue::Long(jlong::from(quality as i64))]
    ).expect("Should be able to create new CreateProofResult:(long, byte[]) object");

    *result
}

//Test functions
#[no_mangle]
pub extern "system" fn Java_com_horizen_sigproofnative_NaiveThresholdSigProof_nativeVerifyProof(
    _env: JNIEnv,
    // this is the class that owns our
    // static method. Not going to be
    // used, but still needs to have
    // an argument slot
    _class: JClass,
    _bt_list: jobjectArray,
    _end_epoch_block_hash: jbyteArray,
    _prev_end_epoch_block_hash: jbyteArray,
    _constant: JObject,
    _quality: jlong,
    _sc_proof_bytes: jbyteArray,
    _check_proof: jboolean,
    _verification_key_path: JString,
    _check_vk: jboolean,
) -> jboolean {

    //Extract backward transfers
    let mut bt_list = vec![];

    let bt_list_size = _env.get_array_length(_bt_list)
        .expect("Should be able to get bt_list size");

    if bt_list_size > 0 {
        for i in 0..bt_list_size {
            let o = _env.get_object_array_element(_bt_list, i)
                .expect(format!("Should be able to get elem {} of bt_list array", i).as_str());


            let pk: [u8; 20] = {
                let p = _env.call_method(o, "getPublicKeyHash", "()[B", &[])
                    .expect("Should be able to call getPublicKeyHash method").l().unwrap().cast();

                let mut pk_bytes = [0u8; 20];

                _env.convert_byte_array(p)
                    .expect("Should be able to convert to Rust byte array")
                    .write(&mut pk_bytes[..])
                    .expect("Should be able to write into byte array of fixed size");

                pk_bytes
            };

            let a = _env.call_method(o, "getAmount", "()J", &[])
                .expect("Should be able to call getAmount method").j().unwrap() as u64;

            bt_list.push(BackwardTransfer::new(pk, a));
        }
    }

    //Extract block hashes
    let end_epoch_block_hash = {
        let t = _env.convert_byte_array(_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        end_epoch_block_hash_bytes
    };

    let prev_end_epoch_block_hash = {
        let t = _env.convert_byte_array(_prev_end_epoch_block_hash)
            .expect("Should be able to convert to Rust array");

        let mut prev_end_epoch_block_hash_bytes = [0u8; 32];

        t.write(&mut prev_end_epoch_block_hash_bytes[..])
            .expect("Should be able to write into byte array of fixed size");

        prev_end_epoch_block_hash_bytes
    };

    //Extract constant
    let constant = {

        let c =_env.get_field(_constant, "fieldElementPointer", "J")
            .expect("Should be able to get field fieldElementPointer");

        read_raw_pointer(c.j().unwrap() as *const FieldElement)
    };

    //Extract quality
    let quality = _quality as u64;

    //Extract proof
    let proof_bytes = _env.convert_byte_array(_sc_proof_bytes)
        .expect("Should be able to convert to Rust byte array");
    let result = if _check_proof == JNI_TRUE {
        deserialize_from_buffer_checked(proof_bytes.as_slice())
    } else {
        deserialize_from_buffer(proof_bytes.as_slice())
    };
    let proof = match result {
        Ok(proof) => proof,
        Err(_) => return JNI_FALSE // I/O ERROR
    };

    //Extract vk path
    let vk_path = _env.get_string(_verification_key_path)
        .expect("Should be able to read jstring as Rust String");

    //Verify proof
    match verify_naive_threshold_sig_proof(
        constant,
        &end_epoch_block_hash,
        &prev_end_epoch_block_hash,
        bt_list.as_slice(),
        quality,
        &proof,
        vk_path.to_str().unwrap(),
        _check_vk == JNI_TRUE,

    ) {
        Ok(result) => if result { JNI_TRUE } else { JNI_FALSE },
        Err(_) => JNI_FALSE // CRYPTO_ERROR or IO_ERROR
    }
}