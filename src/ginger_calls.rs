use algebra::{fields::{
    bn_382::{Fr, Fq as ScalarFieldElement}, PrimeField
}, curves::{
    bn_382::Bn382 as PairingCurve,
    bn_382::g::{
        Projective as GroupProjective, Affine as GroupAffine
    },
}, FromBytes, FromBytesChecked, validity::SemanticallyValid,
   ToBytes, BigInteger384, ProjectiveCurve, AffineCurve, ToConstraintField, UniformRand, ToBits};
use primitives::{crh::{
    poseidon::parameters::bn382::{
        BN382FrPoseidonHash, BN382FrBatchPoseidonHash as BatchFieldHash
    },
    FieldBasedHash,
    bowe_hopwood::{
        BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters
    }
}};

use rand::{
    SeedableRng, rngs::OsRng
};
use rand_xorshift::XorShiftRng;

use std::{
    fs::File, io::Result as IoResult, path::Path
};
use lazy_static::*;

pub type FieldElement = Fr;

pub const FIELD_SIZE: usize = 48; //Field size in bytes
pub const SCALAR_FIELD_SIZE: usize = FIELD_SIZE;// 48
pub const G1_SIZE: usize = 97;
pub const G2_SIZE: usize = 193;

pub type Error = Box<dyn std::error::Error>;

//*******************************Generic functions**********************************************
// Note: Should decide if panicking or handling IO errors

pub fn deserialize_from_buffer<T: FromBytes>(buffer: &[u8]) ->  IoResult<T> {
    T::read(buffer)
}

pub fn deserialize_from_buffer_checked<T: FromBytesChecked>(buffer: &[u8]) ->  IoResult<T> {
    T::read_checked(buffer)
}

pub fn serialize_to_buffer<T: ToBytes>(to_write: &T, buffer: &mut [u8]) -> IoResult<()> {
    to_write.write(buffer)
}

pub fn read_from_file<T: FromBytes>(file_path: &str) -> IoResult<T>{
    let mut fs = File::open(file_path)?;
    T::read(&mut fs)
}

pub fn read_from_file_checked<T: FromBytesChecked>(file_path: &str) -> IoResult<T>{
    let mut fs = File::open(file_path)?;
    T::read_checked(&mut fs)
}

pub fn is_valid<T: SemanticallyValid>(to_check: &T) -> bool {
    T::is_valid(to_check)
}

// NOTE: This function relies on a non-cryptographically safe RNG, therefore it
// must be used ONLY for testing purposes
pub fn get_random_field_element(seed: u64) -> FieldElement {
    let mut rng = XorShiftRng::seed_from_u64(seed);
    FieldElement::rand(&mut rng)
}

//Will return error if buffer.len > FIELD_SIZE. If buffer.len < FIELD_SIZE, padding 0s will be added
pub fn read_field_element_from_buffer_with_padding(buffer: &[u8]) -> IoResult<FieldElement>
{
    let buff_len = buffer.len();

    //Pad to reach field element size
    let mut new_buffer = vec![];
    new_buffer.extend_from_slice(buffer);
    for _ in buff_len..FIELD_SIZE { new_buffer.push(0u8) } //Add padding zeros to reach field size

    FieldElement::read(&new_buffer[..])
}

pub fn read_field_element_from_u64(num: u64) -> FieldElement {
    FieldElement::from_repr(BigInteger384::from(num))
}

//************************************Poseidon Hash functions****************************************

pub type FieldHash = BN382FrPoseidonHash;

pub fn get_poseidon_hash(personalization: Option<&[FieldElement]>) -> FieldHash {
    FieldHash::init(personalization)
}

pub fn update_poseidon_hash(hash: &mut FieldHash, input: &FieldElement){
    hash.update(*input);
}

pub fn reset_poseidon_hash(hash: &mut FieldHash, personalization: Option<&[FieldElement]>){
    hash.reset(personalization);
}

pub fn finalize_poseidon_hash(hash: &FieldHash) -> FieldElement{
    hash.finalize()
}



#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;
    use algebra::{to_bytes, ToBytes, Field};

    #[test]
    fn sample_calls_poseidon_hash(){
        let mut rng = OsRng;
        let hash_input = vec![FieldElement::rand(&mut rng); 2];
        let mut h = get_poseidon_hash(None);

        //Compute poseidon hash
        update_poseidon_hash(&mut h, &hash_input[0]);
        update_poseidon_hash(&mut h, &hash_input[1]);
        let h_output = finalize_poseidon_hash(&h);

        //Call to finalize keeps the state
        reset_poseidon_hash(&mut h, None);
        update_poseidon_hash(&mut h, &hash_input[0]);
        finalize_poseidon_hash(&h); //Call to finalize() keeps the state
        update_poseidon_hash(&mut h, &hash_input[1]);
        assert_eq!(h_output, finalize_poseidon_hash(&h));

        //finalize() is idempotent
        assert_eq!(h_output, finalize_poseidon_hash(&h));
    }
}