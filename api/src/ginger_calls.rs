use algebra::{fields::{
    mnt4753::{Fr, Fq as ScalarFieldElement}, PrimeField
}, curves::{
    mnt4753::MNT4 as PairingCurve,
    mnt6753::{
        G1Projective as GroupProjective, G1Affine as GroupAffine
    },
}, FromBytes, FromBytesChecked, validity::SemanticallyValid,
   ToBytes, BigInteger768, ProjectiveCurve, AffineCurve, ToConstraintField, UniformRand, ToBits};
use primitives::{crh::{
    poseidon::parameters::mnt4753::{MNT4PoseidonHash, MNT4BatchPoseidonHash as BatchFieldHash},
    FieldBasedHash,
    bowe_hopwood::{
        BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters
    },
}, merkle_tree::field_based_mht::{
    smt::{BigMerkleTree, LazyBigMerkleTree, Coord, OperationLeaf},
    optimized::FieldBasedOptimizedMHT,
    parameters::mnt4753::{MNT4753_PHANTOM_MERKLE_ROOT as PHANTOM_MERKLE_ROOT, MNT4753_MHT_POSEIDON_PARAMETERS as MHT_PARAMETERS},
    FieldBasedMerkleTree, FieldBasedMerkleTreePrecomputedEmptyConstants,
    FieldBasedMerkleTreeParameters, BatchFieldBasedMerkleTreeParameters,
    FieldBasedMerkleTreePath, FieldBasedBinaryMHTPath,
}, signature::{
    FieldBasedSignatureScheme, schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrSignature,
        FieldBasedSchnorrPk,
    },
}, vrf::{FieldBasedVrf, ecvrf::*}, ActionLeaf};
use proof_systems::groth16::{
    Proof, create_random_proof,
    prepare_verifying_key, verify_proof,
};
use circuits::demo_circuit::{
    constants::{
        VRFParams, VRFWindow,
    },
    naive_threshold_sig::*
};
use rand::{
    SeedableRng, rngs::OsRng
};
use rand_xorshift::XorShiftRng;

use std::{
    fs::File, io::Result as IoResult, path::Path
};
use lazy_static::*;

pub type FieldElement = Fr;

pub const FIELD_SIZE: usize = 96; //Field size in bytes
pub const SCALAR_FIELD_SIZE: usize = FIELD_SIZE;// 96
pub const G1_SIZE: usize = 193;
pub const G2_SIZE: usize = 385;

pub const SCHNORR_PK_SIZE: usize = G1_SIZE; // 193
pub const SCHNORR_SK_SIZE: usize = SCALAR_FIELD_SIZE; // 96
pub const SCHNORR_SIG_SIZE: usize = 2 * FIELD_SIZE; // 192

pub const VRF_PK_SIZE: usize = G1_SIZE; // 193
pub const VRF_SK_SIZE: usize = SCALAR_FIELD_SIZE; // 96
pub const VRF_PROOF_SIZE: usize = G1_SIZE + 2 * FIELD_SIZE; // 192

pub const ZK_PROOF_SIZE: usize = 2 * G1_SIZE + G2_SIZE;  // 771
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

//***************************Schnorr types and functions********************************************

pub type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<FieldElement, GroupProjective, FieldHash>;
pub type SchnorrSig = FieldBasedSchnorrSignature<FieldElement, GroupProjective>;
pub type SchnorrPk = GroupAffine;
pub type SchnorrSk = ScalarFieldElement;

pub fn schnorr_generate_key() -> (SchnorrPk, SchnorrSk) {
    let mut rng = OsRng;
    let (pk, sk) = SchnorrSigScheme::keygen(&mut rng);
    (pk.0.into_affine(), sk)
}

pub fn schnorr_get_public_key(sk: &SchnorrSk) -> SchnorrPk {
    SchnorrSigScheme::get_public_key(sk).0.into_affine()
}

pub fn schnorr_verify_public_key(pk: &SchnorrPk) -> bool {
    SchnorrSigScheme::keyverify(&FieldBasedSchnorrPk(pk.into_projective()))
}

pub fn schnorr_sign(msg: &FieldElement, sk: &SchnorrSk, pk: &SchnorrPk) -> Result<SchnorrSig, Error> {
    let mut rng = OsRng;
    SchnorrSigScheme::sign(&mut rng, &FieldBasedSchnorrPk(pk.into_projective()), sk, &[*msg])
}

pub fn schnorr_verify_signature(msg: &FieldElement, pk: &SchnorrPk, signature: &SchnorrSig) -> Result<bool, Error> {
    SchnorrSigScheme::verify(&FieldBasedSchnorrPk(pk.into_projective()), &[*msg], signature)
}

//************************************Poseidon Hash functions****************************************

pub type FieldHash = MNT4PoseidonHash;

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

//*****************************Naive threshold sig circuit related functions************************

pub type SCProof = Proof<PairingCurve>;

#[derive(Clone, Default)]
pub struct BackwardTransfer {
    pub pk_dest:    [u8; 20],
    pub amount:     u64,
}

impl BackwardTransfer {
    pub fn new(pk_dest: [u8; 20], amount: u64) -> Self
    {
        Self{ pk_dest, amount }
    }

    pub fn to_field_element(&self) -> IoResult<FieldElement>
    {
        let mut buffer = vec![];
        self.pk_dest.write(&mut buffer)?;
        self.amount.write(&mut buffer)?;
        read_field_element_from_buffer_with_padding(buffer.as_slice())
    }
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
    FieldElement::from_repr(BigInteger768::from(num))
}

// Computes H(H(pks), threshold): used to generate the constant value needed to be declared
// in MC during SC creation.
pub fn compute_pks_threshold_hash(pks: &[SchnorrPk], threshold: u64) -> FieldElement {
    let threshold_field = read_field_element_from_u64(threshold);
    let mut h = FieldHash::init(None);
    pks.iter().for_each(|pk| { h.update(pk.x); });
    let pks_hash = h.finalize();
    h
        .reset(None)
        .update(pks_hash)
        .update(threshold_field)
        .finalize()
}

const BT_MERKLE_TREE_HEIGHT: usize = 12;

fn compute_bt_root(bts: &[FieldElement]) -> Result<FieldElement, Error> {
    let mut bt_mt =
        GingerMHT::init(BT_MERKLE_TREE_HEIGHT, 2usize.pow(BT_MERKLE_TREE_HEIGHT as u32));
    for &bt in bts.iter(){
        bt_mt.append(bt);
    }
    bt_mt.finalize_in_place();
    bt_mt.root().ok_or(Error::from("Failed to compute BT Merkle Tree root"))
}

//Compute and return (MR(bt_list), H(MR(bt_list), H(bi-1), H(bi))
pub fn compute_msg_to_sign(
    end_epoch_mc_b_hash:      &FieldElement,
    prev_end_epoch_mc_b_hash: &FieldElement,
    bt_list:                  &[BackwardTransfer],
) -> Result<(FieldElement, FieldElement), Error> {

    let mr_bt = if bt_list.is_empty() {
        PHANTOM_MERKLE_ROOT //Note: Can actually be taken from MHT_PARAMETERS::nodes[BT_MERKLE_TREE_HEIGHT]
    } else {
        let mut bt_field_list = vec![];
        for bt in bt_list.iter() {
            let bt_f = bt.to_field_element()?;
            bt_field_list.push(bt_f);
        }

        //Compute bt_list merkle_root
        compute_bt_root(bt_field_list.as_slice())?
    };

    //Compute message to be verified
    let msg = FieldHash::init(None)
        .update(mr_bt)
        .update(*prev_end_epoch_mc_b_hash)
        .update(*end_epoch_mc_b_hash)
        .finalize();

    Ok((mr_bt, msg))
}

pub fn compute_wcert_sysdata_hash(
    valid_sigs:               u64,
    mr_bt:                    &FieldElement,
    prev_end_epoch_mc_b_hash: &FieldElement,
    end_epoch_mc_b_hash:      &FieldElement,
) -> Result<FieldElement, Error> {

    //Compute quality and wcert_sysdata_hash
    let quality = read_field_element_from_u64(valid_sigs);
    let wcert_sysdata_hash = FieldHash::init(None)
        .update(quality)
        .update(*mr_bt)
        .update(*prev_end_epoch_mc_b_hash)
        .update(*end_epoch_mc_b_hash)
        .finalize();
    Ok(wcert_sysdata_hash)
}

pub fn create_naive_threshold_sig_proof(
    pks:                      &[SchnorrPk],
    mut sigs:                 Vec<Option<SchnorrSig>>,
    end_epoch_mc_b_hash:      &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list:                  &[BackwardTransfer],
    threshold:                u64,
    proving_key_path:         &str,
    enforce_membership:       bool,
) -> Result<(SCProof, u64), Error> {

    //Get max pks
    let max_pks = pks.len();
    assert_eq!(sigs.len(), max_pks);

    //Read end_epoch_mc_b_hash, prev_end_epoch_mc_b_hash and bt_list as field elements
    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..])?;
    let prev_end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..])?;
    let (mr_bt, msg) = compute_msg_to_sign(
        &end_epoch_mc_b_hash,
        &prev_end_epoch_mc_b_hash,
        bt_list,
    )?;

    // Iterate over sigs, check and count number of valid signatures,
    // and replace with NULL_CONST.null_sig the None ones
    let mut valid_signatures = 0;
    for i in 0..max_pks {
        if sigs[i].is_some(){
            let is_verified = schnorr_verify_signature(&msg, &pks[i], &sigs[i].unwrap())?;
            if is_verified { valid_signatures += 1; }
        }
        else {
            sigs[i] = Some(NULL_CONST.null_sig)
        }
    }

    //Compute b as v-t and convert it to field element
    let b = read_field_element_from_u64(valid_signatures - threshold);

    //Convert affine pks to projective
    let pks = pks.iter().map(|&pk| FieldBasedSchnorrPk(pk.into_projective())).collect::<Vec<_>>();

    //Convert needed variables into field elements
    let threshold = read_field_element_from_u64(threshold);

    let c = NaiveTresholdSignature::<FieldElement>::new(
        pks, sigs, threshold, b, end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash, mr_bt, max_pks,
    );

    //Read proving key
    let params = if enforce_membership {
        read_from_file_checked(proving_key_path)
    } else {
        read_from_file(proving_key_path)
    }?;

    //Create and return proof
    let mut rng = OsRng;
    let proof = create_random_proof(c, &params, &mut rng)?;
    Ok((proof, valid_signatures))
}

pub fn verify_naive_threshold_sig_proof(
    constant:                 &FieldElement,
    end_epoch_mc_b_hash:      &[u8; 32],
    prev_end_epoch_mc_b_hash: &[u8; 32],
    bt_list:                  &[BackwardTransfer],
    valid_sigs:               u64,
    proof:                    &SCProof,
    vk_path:                  &str,
    enforce_membership:       bool
) -> Result<bool, Error>
{
    //Compute wcert_sysdata_hash
    let end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..])?;
    let prev_end_epoch_mc_b_hash = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..])?;
    let (mr_bt, _) = compute_msg_to_sign(&end_epoch_mc_b_hash, &prev_end_epoch_mc_b_hash, bt_list)?;
    let wcert_sysdata_hash = compute_wcert_sysdata_hash(valid_sigs, &mr_bt, &prev_end_epoch_mc_b_hash, &end_epoch_mc_b_hash)?;
    let aggregated_input = FieldHash::init(None)
        .update(*constant)
        .update(wcert_sysdata_hash)
        .finalize();

    //Verify proof
    let vk = if enforce_membership {
        read_from_file_checked(vk_path)
    } else {
        read_from_file(vk_path)
    }?;
    let pvk = prepare_verifying_key(&vk); //Get verifying key
    let is_verified = verify_proof(&pvk, &proof, &[aggregated_input])?;

    Ok(is_verified)
}

//VRF types and functions

lazy_static! {
    pub static ref VRF_GH_PARAMS: BoweHopwoodPedersenParameters<GroupProjective> = {
        let params = VRFParams::new();
        BoweHopwoodPedersenParameters::<GroupProjective>{generators: params.group_hash_generators}
    };
}

type GroupHash = BoweHopwoodPedersenCRH<GroupProjective, VRFWindow>;

pub type VRFScheme = FieldBasedEcVrf<FieldElement, GroupProjective, FieldHash, GroupHash>;
pub type VRFProof = FieldBasedEcVrfProof<FieldElement, GroupProjective>;
pub type VRFPk = GroupAffine;
pub type VRFSk = ScalarFieldElement;

pub fn vrf_generate_key() -> (VRFPk, VRFSk) {
    let mut rng = OsRng;
    let (pk, sk) = VRFScheme::keygen(&mut rng);
    (pk.0.into_affine(), sk)
}

pub fn vrf_get_public_key(sk: &VRFSk) -> VRFPk {
    VRFScheme::get_public_key(sk).0.into_affine()
}

pub fn vrf_verify_public_key(pk: &VRFPk) -> bool {
    VRFScheme::keyverify(&FieldBasedEcVrfPk(pk.into_projective()))
}

pub fn vrf_prove(msg: &FieldElement, sk: &VRFSk, pk: &VRFPk) -> Result<(VRFProof, FieldElement), Error> {
    let mut rng = OsRng;

    //Compute proof
    let proof = VRFScheme::prove(
        &mut rng,
        &VRF_GH_PARAMS,
        &FieldBasedEcVrfPk(pk.into_projective()),
        sk,
        &[*msg]
    )?;

    //Convert gamma from proof to field elements
    let gamma_coords = proof.gamma.to_field_elements().unwrap();

    //Compute VRF output
    let mut hash_input = Vec::new();
    hash_input.push(*msg);
    hash_input.extend_from_slice(gamma_coords.as_slice());
    let output = {
        let mut h = FieldHash::init(None);
        h.update(*msg);
        gamma_coords.into_iter().for_each(|c| { h.update(c); });
        h.finalize()
    };

    Ok((proof, output))
}

pub fn vrf_proof_to_hash(msg: &FieldElement, pk: &VRFPk, proof: &VRFProof) -> Result<FieldElement, Error> {
    VRFScheme::proof_to_hash(&VRF_GH_PARAMS,&FieldBasedEcVrfPk(pk.into_projective()), &[*msg], proof)
}

//************Merkle Tree functions******************

////////////MERKLE_PATH
pub type GingerMHTPath = FieldBasedBinaryMHTPath<GingerMerkleTreeParameters>;

pub fn verify_ginger_merkle_path(
    path: &GingerMHTPath,
    height: usize,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify(height, leaf, root)
}

pub fn verify_ginger_merkle_path_without_length_check(
    path: &GingerMHTPath,
    leaf: &FieldElement,
    root: &FieldElement
) -> Result<bool, Error> {
    path.verify_without_length_check(leaf, root)
}

pub fn is_path_leftmost(path: &GingerMHTPath) -> bool {
    path.is_leftmost()
}

pub fn is_path_rightmost(path: &GingerMHTPath) -> bool {
    path.is_rightmost()
}

pub fn is_path_non_empty_rightmost(path: &GingerMHTPath) -> bool { path.is_non_empty_rightmost() }

pub fn get_leaf_index_from_path(path: &GingerMHTPath) -> u64 {
    path.leaf_index() as u64
}

pub fn get_path_size_in_bytes(path: &GingerMHTPath) -> usize {
    ((1 + FIELD_SIZE) * path.get_length()) + 1
}

pub fn apply(path: &GingerMHTPath, leaf: &FieldElement) -> FieldElement
{
    let mut digest = FieldHash::init(None);
    let mut prev_node = *leaf;
    for &(sibling, direction) in path.get_raw_path().as_slice() {

        // Choose left and right hash according to direction
        let (left, right) = if !direction {
            (prev_node, sibling)
        } else {
            (sibling, prev_node)
        };

        // Compute the parent node
        prev_node = digest
            .update(left)
            .update(right)
            .finalize();

        digest.reset(None);
    }
    prev_node
}

////////////OPTIMIZED MERKLE TREE

#[derive(Debug, Clone)]
pub struct GingerMerkleTreeParameters;

impl FieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type Data = FieldElement;
    type H = FieldHash;
    const MERKLE_ARITY: usize = 2;
    const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> =
        Some(MHT_PARAMETERS);
}

impl BatchFieldBasedMerkleTreeParameters for GingerMerkleTreeParameters {
    type BH = BatchFieldHash;
}

pub type GingerMHT = FieldBasedOptimizedMHT<GingerMerkleTreeParameters>;

pub fn new_ginger_mht(height: usize, processing_step: usize) -> GingerMHT {
    GingerMHT::init(height, processing_step)
}

pub fn append_leaf_to_ginger_mht(tree: &mut GingerMHT, leaf: &FieldElement){
    tree.append(*leaf);
}

pub fn finalize_ginger_mht(tree: &GingerMHT) -> GingerMHT {
    tree.finalize()
}

pub fn finalize_ginger_mht_in_place(tree: &mut GingerMHT) {
    tree.finalize_in_place();
}

pub fn get_ginger_mht_root(tree: &GingerMHT) -> Option<FieldElement> {
    tree.root()
}

pub fn get_ginger_mht_path(tree: &GingerMHT, leaf_index: u64) -> Option<GingerMHTPath> {
    match tree.get_merkle_path(leaf_index as usize) {
        Some(path) => Some(path.into()),
        None => None,
    }
}

pub fn reset_ginger_mht(tree: &mut GingerMHT){
    tree.reset();
}

////////////SPARSE MERKLE TREE

pub type GingerSMT = BigMerkleTree<GingerMerkleTreeParameters>;

// Note: If position is non empty in the SMTs the old leaf will be overwritten.
// If that's not the desired behaviour, then leaf should depend on some tweakable
// parameter that allows to re-compute a new position for it, possibly multiple times.
// Therefore, it is advisable to minimize the risk of having collisions,or to handle
// them
pub fn leaf_to_index(leaf: &FieldElement, height: usize) -> u64 {

    // Convert field element to bits
    let bits = leaf.write_bits();
    assert!(height <= bits.len());

    // Use log_2(num_leaves) MSB of serialized FieldElement to estabilish leaf position inside
    // the tree
    let leaf_bits = &bits[..height];
    let position = leaf_bits.iter().rev().fold(0, |acc, &b| acc*2 + b as u64);
    position
}

pub fn get_ginger_smt(height: usize, db_path: &str) -> Result<GingerSMT, Error>{

    // If at least the leaves database is available, we can restore the tree
    if Path::new(db_path).exists() {
        restore_ginger_smt(height, db_path)
    } else { // Otherwise we need to create a new tree
        new_ginger_smt(height, db_path)
    }
}

fn new_ginger_smt(height: usize, db_path: &str) -> Result<GingerSMT, Error> {
    match GingerSMT::new(
        height,
        true,
        db_path.to_owned(),
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

fn restore_ginger_smt(height: usize, db_path: &str) -> Result<GingerSMT, Error>
{
    match GingerSMT::load_batch::<GingerMerkleTreeParameters>(
        height,
        true,
        db_path.to_owned(),
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

pub fn flush_ginger_smt(tree: &mut GingerSMT) {
    tree.flush()
}

pub fn set_ginger_smt_persistency(tree: &mut GingerSMT, persistency: bool) {
    tree.set_persistency(persistency);
}

pub fn get_position_in_ginger_smt(tree: &GingerSMT, leaf: &FieldElement) -> u64
{
    leaf_to_index(leaf, tree.height())
}

pub fn is_position_empty_in_ginger_smt(tree: &GingerSMT, position: u64) -> bool {
    tree.is_leaf_empty(Coord::new(0, position as usize))
}

pub fn add_leaf_to_ginger_smt(tree: &mut GingerSMT, leaf: &FieldElement, position: u64){
    tree.insert_leaf(Coord::new(0, position as usize), *leaf);
}

pub fn remove_leaf_from_ginger_smt(tree: &mut GingerSMT, position: u64){
    tree.remove_leaf(Coord::new(0, position as usize));
}

pub fn get_ginger_smt_root(tree: &GingerSMT) -> FieldElement {
    tree.get_root()
}

pub fn get_ginger_smt_path(tree: &mut GingerSMT, leaf_position: u64) -> GingerMHTPath {
    tree.get_merkle_path(Coord::new(0, leaf_position as usize))
}

////////////LAZY SPARSE MERKLE TREE

pub type LazyGingerSMT = LazyBigMerkleTree<GingerMerkleTreeParameters>;
type GingerLeaf = OperationLeaf<FieldElement>;

pub fn get_lazy_ginger_smt(height: usize, db_path: &str) -> Result<LazyGingerSMT, Error>{

    // If at least the leaves database is available, we can restore the tree
    if Path::new(db_path).exists() {
        restore_lazy_ginger_smt(height, db_path)
    } else { // Otherwise we need to create a new tree
        new_lazy_ginger_smt(height, db_path)
    }
}

fn new_lazy_ginger_smt(height: usize, db_path: &str) -> Result<LazyGingerSMT, Error> {
    match LazyGingerSMT::new(
        height,
        true,
        db_path.to_owned(),
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

fn restore_lazy_ginger_smt(height: usize, db_path: &str) -> Result<LazyGingerSMT, Error>
{
    match LazyGingerSMT::load(
        height,
        true,
        db_path.to_owned(),
    ) {
        Ok(tree) => Ok(tree),
        Err(e) => Err(Box::new(e))
    }
}

pub fn flush_lazy_ginger_smt(tree: &mut LazyGingerSMT){
    tree.flush()
}

pub fn set_ginger_lazy_smt_persistency(tree: &mut LazyGingerSMT, persistency: bool) {
    tree.set_persistency(persistency);
}

pub fn get_position_in_lazy_ginger_smt(tree: &LazyGingerSMT, leaf: &FieldElement) -> u64
{
    leaf_to_index(leaf, tree.height())
}

pub fn is_position_empty_in_lazy_ginger_smt(tree: &LazyGingerSMT, position: u64) -> bool {
    tree.is_leaf_empty(Coord::new(0, position as usize))
}

pub fn add_leaves_to_ginger_lazy_smt(tree: &mut LazyGingerSMT, leaves: &[FieldElement]) -> FieldElement{
    let leaves = leaves.iter().map(|leaf| {
        GingerLeaf::new(0, leaf_to_index(leaf, tree.height()) as usize, ActionLeaf::Insert, Some(*leaf))
    }).collect::<Vec<_>>();
    tree.process_leaves(leaves.as_slice())
}

pub fn remove_leaves_from_ginger_lazy_smt(tree: &mut LazyGingerSMT, positions: &[i64]) -> FieldElement{
    let leaves = positions.iter().map(|&position| {
        GingerLeaf::new(0, position as usize, ActionLeaf::Remove, None)
    }).collect::<Vec<_>>();
    tree.process_leaves(leaves.as_slice())
}

pub fn get_lazy_ginger_smt_root(tree: &LazyGingerSMT) -> FieldElement {
    tree.get_root()
}

pub fn get_lazy_ginger_smt_path(tree: &mut LazyGingerSMT, leaf_position: u64) -> GingerMHTPath {
    tree.get_merkle_path(Coord::new(0, leaf_position as usize))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::RngCore;
    use algebra::{to_bytes, ToBytes, Field};

    fn write_to_file<T: ToBytes>(to_write: &T, file_path: &str) -> IoResult<()>{
        let mut fs = File::create(file_path)?;
        to_write.write(&mut fs)?;
        Ok(())
    }

    #[allow(dead_code)]
    fn into_i8(v: Vec<u8>) -> Vec<i8> {
        // first, make sure v's destructor doesn't free the data
        // it thinks it owns when it goes out of scope
        let mut v = std::mem::ManuallyDrop::new(v);

        // then, pick apart the existing Vec
        let p = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();

        // finally, adopt the data into a new Vec
        unsafe { Vec::from_raw_parts(p as *mut i8, len, cap) }
    }

    fn create_sample_naive_threshold_sig_circuit(bt_num: usize) {
        //assume to have 3 pks, threshold = 2
        let mut rng = OsRng;

        //Generate random mc block hashes and bt list
        let mut end_epoch_mc_b_hash = [0u8; 32];
        let mut prev_end_epoch_mc_b_hash = [0u8; 32];
        rng.fill_bytes(&mut end_epoch_mc_b_hash);
        rng.fill_bytes(&mut prev_end_epoch_mc_b_hash);
        println!("end epoch u8: {:?}", end_epoch_mc_b_hash);
        println!("prev end epoch u8: {:?}", prev_end_epoch_mc_b_hash);
        println!("end epoch i8: {:?}", into_i8(end_epoch_mc_b_hash.to_vec()));
        println!("prev end epoch i8: {:?}", into_i8(prev_end_epoch_mc_b_hash.to_vec()));
        let end_epoch_mc_b_hash_f = read_field_element_from_buffer_with_padding(&end_epoch_mc_b_hash[..]).unwrap();
        let prev_end_epoch_mc_b_hash_f = read_field_element_from_buffer_with_padding(&prev_end_epoch_mc_b_hash[..]).unwrap();

        let mut bt_list = vec![];
        for _ in 0..bt_num {
            bt_list.push(BackwardTransfer::default());
        }

        //Compute msg to sign
        let (_, msg) = compute_msg_to_sign(
            &end_epoch_mc_b_hash_f,
            &prev_end_epoch_mc_b_hash_f,
            bt_list.as_slice()
        ).unwrap();

        //Generate params and write them to file
        let params = generate_parameters(3).unwrap();
        let proving_key_path = if bt_num != 0 {"./sample_params"} else {"./sample_params_no_bwt"};
        write_to_file(&params, proving_key_path).unwrap();

        let verifying_key_path = if bt_num != 0 {"./sample_vk"} else {"./sample_vk_no_bwt"};
        write_to_file(&(params.vk), verifying_key_path).unwrap();

        //Generate sample pks and sigs vec
        let threshold: u64 = 2;
        let mut pks = vec![];
        let mut sks = vec![];
        for _ in 0..3 {
            let keypair = schnorr_generate_key();
            pks.push(keypair.0);
            sks.push(keypair.1);
            println!("sk: {:?}", into_i8(to_bytes!(keypair.1).unwrap()).to_vec());
        }

        let mut sigs = vec![];
        sigs.push(Some(schnorr_sign(&msg, &sks[0], &pks[0]).unwrap()));
        sigs.push(None);
        sigs.push(Some(schnorr_sign(&msg, &sks[2], &pks[2]).unwrap()));

        println!("sk: {:?}", into_i8(to_bytes!(sks[0]).unwrap()));
        println!("sk: {:?}", into_i8(to_bytes!(sks[2]).unwrap()));
        println!("sk: {:?}", into_i8(to_bytes!(sks[1]).unwrap()));

        println!("sig: {:?}", into_i8(to_bytes!(sigs[0].unwrap()).unwrap()));
        println!("sig: {:?}", into_i8(to_bytes!(sigs[2].unwrap()).unwrap()));

        let constant = compute_pks_threshold_hash(pks.as_slice(), threshold);
        println!("Constant u8: {:?}", to_bytes!(constant).unwrap());

        //Create and serialize proof
        let (proof, quality) = create_naive_threshold_sig_proof(
            pks.as_slice(),
            sigs,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            threshold,
            proving_key_path,
            false,
        ).unwrap();
        let proof_path = if bt_num != 0 {"./sample_proof"} else {"./sample_proof_no_bwt"};
        write_to_file(&proof, proof_path).unwrap();

        //Verify proof
        assert!(verify_naive_threshold_sig_proof(
            &constant,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            quality,
            &proof,
            verifying_key_path,
            true,
        ).unwrap());


        //Generate wrong public inputs by changing quality and assert proof verification doesn't pass
        assert!(!verify_naive_threshold_sig_proof(
            &constant,
            &end_epoch_mc_b_hash,
            &prev_end_epoch_mc_b_hash,
            bt_list.as_slice(),
            quality - 1,
            &proof,
            verifying_key_path,
            true,
        ).unwrap());
    }

    #[test]
    fn sample_calls_naive_threshold_sig_circuit() {
        println!("****************With BWT**********************");
        create_sample_naive_threshold_sig_circuit(10);
        println!("****************Without BWT*******************");
        create_sample_naive_threshold_sig_circuit(0);
    }

    #[test]
    fn sample_calls_schnorr_sig_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);

        let (pk, sk) = schnorr_generate_key(); //Keygen
        assert_eq!(schnorr_get_public_key(&sk), pk); //Get pk
        assert!(schnorr_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let mut pk_serialized = vec![0u8; SCHNORR_PK_SIZE];
        serialize_to_buffer(&pk, &mut pk_serialized).unwrap();
        let pk_deserialized: SchnorrPk = deserialize_from_buffer_checked(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let mut sk_serialized = vec![0u8; SCHNORR_SK_SIZE];
        serialize_to_buffer(&sk, &mut sk_serialized).unwrap();
        let sk_deserialized = deserialize_from_buffer(&sk_serialized).unwrap();
        assert_eq!(sk, sk_deserialized);

        let sig = schnorr_sign(&msg, &sk, &pk).unwrap(); //Sign msg
        assert!(is_valid(&sig));

        //Serialize/deserialize sig
        let mut sig_serialized = vec![0u8; SCHNORR_SIG_SIZE];
        serialize_to_buffer(&sig, &mut sig_serialized).unwrap();
        let sig_deserialized = deserialize_from_buffer(&sig_serialized).unwrap();
        assert_eq!(sig, sig_deserialized);

        assert!(schnorr_verify_signature(&msg, &pk, &sig).unwrap()); //Verify sig

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(!schnorr_verify_signature(&wrong_msg, &pk, &sig).unwrap());
    }

    #[test]
    fn sample_calls_vrf_prove_verify(){
        let mut rng = OsRng;
        let msg = FieldElement::rand(&mut rng);

        let (pk, sk) = vrf_generate_key(); //Keygen
        assert_eq!(vrf_get_public_key(&sk), pk); //Get pk
        assert!(vrf_verify_public_key(&pk)); //Verify pk

        //Serialize/deserialize pk
        let mut pk_serialized = vec![0u8; VRF_PK_SIZE];
        serialize_to_buffer(&pk, &mut pk_serialized).unwrap();
        let pk_deserialized: VRFPk = deserialize_from_buffer_checked(&pk_serialized).unwrap();
        assert_eq!(pk, pk_deserialized);

        //Serialize/deserialize sk
        let mut sk_serialized = vec![0u8; VRF_SK_SIZE];
        serialize_to_buffer(&sk, &mut sk_serialized).unwrap();
        let sk_deserialized = deserialize_from_buffer(&sk_serialized).unwrap();
        assert_eq!(sk, sk_deserialized);

        let (vrf_proof, vrf_out) = vrf_prove(&msg, &sk, &pk).unwrap(); //Create vrf proof for msg
        assert!(is_valid(&vrf_proof));

        //Serialize/deserialize vrf proof
        let mut proof_serialized = vec![0u8; VRF_PROOF_SIZE];
        serialize_to_buffer(&vrf_proof, &mut proof_serialized).unwrap();
        let proof_deserialized = deserialize_from_buffer_checked(&proof_serialized).unwrap();
        assert_eq!(vrf_proof, proof_deserialized);

        //Serialize/deserialize vrf out (i.e. a field element)
        let mut vrf_out_serialized = vec![0u8; FIELD_SIZE];
        serialize_to_buffer(&vrf_out, &mut vrf_out_serialized).unwrap();
        let vrf_out_deserialized = deserialize_from_buffer(&vrf_out_serialized).unwrap();
        assert_eq!(vrf_out, vrf_out_deserialized);

        let vrf_out_dup = vrf_proof_to_hash(&msg, &pk, &vrf_proof).unwrap(); //Verify vrf proof and get vrf out for msg
        assert_eq!(vrf_out, vrf_out_dup);

        //Negative case
        let wrong_msg = FieldElement::rand(&mut rng);
        assert!(vrf_proof_to_hash(&wrong_msg, &pk, &vrf_proof).is_err());
    }

    #[test]
    fn sample_calls_merkle_tree(){
        let height = 10;
        let leaves_num = 2usize.pow(3 as u32);
        let mut leaves = vec![];
        let mut positions = vec![];
        let mut rng = OsRng;

        // Get GingerSMT
        let mut smt = get_ginger_smt(
            height,
            "./temp_db",
        ).unwrap();

        // Add leaves to GingerSMT in different positions
        for _ in 0..leaves_num {
            loop {
                let r = FieldElement::rand(&mut rng);
                let position = get_position_in_ginger_smt(&smt, &r);
                if is_position_empty_in_ginger_smt(&smt, position) { //Ensure that each leaf ends up in a different position
                    leaves.push(r);
                    positions.push(position);
                    println!("Leaf: {:?}", into_i8(to_bytes!(r).unwrap()));
                    println!("Position: {:?}", position);
                    println!("__________________");
                    add_leaf_to_ginger_smt(&mut smt, &r, position as u64);
                    break;
                }
            }
        }

        //Remove first and last leaves
        remove_leaf_from_ginger_smt(&mut smt, positions[0]);
        remove_leaf_from_ginger_smt(&mut smt, positions[leaves_num - 1]);

        //Get root of GingerSMT
        let smt_root = get_ginger_smt_root(&smt);

        // Get LazyGingerSMT
        let mut lazy_smt = get_lazy_ginger_smt(
            height,
            "./temp_db_lazy",
        ).unwrap();

        // No conflicts here because we ensured each leaf to fall in a different position
        add_leaves_to_ginger_lazy_smt(&mut lazy_smt, leaves.as_slice());

        // Remove first and last leaves
        let lazy_smt_root = remove_leaves_from_ginger_lazy_smt(&mut lazy_smt, &[positions[0] as i64, positions[(leaves_num - 1)] as i64]);

        assert_eq!(smt_root, lazy_smt_root);

        //Get GingerMHT
        let mut mht = new_ginger_mht(height, leaves_num);

        // Must place the leaves at the same positions of the previous trees
        let mut mht_leaves = vec![FieldElement::zero(); 2usize.pow(height as u32)];
        for i in 1..(leaves_num - 1){
            mht_leaves[positions[i] as usize] = leaves[i];
        }

        // Append leaves to the tree and compute the root
        mht_leaves.iter().for_each(|leaf| { append_leaf_to_ginger_mht(&mut mht, leaf) });
        finalize_ginger_mht_in_place(&mut mht);
        let mht_root = get_ginger_mht_root(&mht).expect("Tree must've been finalized");

        assert_eq!(mht_root, lazy_smt_root);

        //Delete SMTs data
        set_ginger_smt_persistency(&mut smt, false);
        set_ginger_lazy_smt_persistency(&mut lazy_smt, false);
    }

    #[test]
    fn sample_calls_merkle_path() {
        let height = 6;
        let leaves_num = 2usize.pow(height as u32);

        // Get GingerMHT
        let mut mht = new_ginger_mht(height, leaves_num);

        // Add leaves
        let mut mht_leaves = Vec::with_capacity(leaves_num);
        for i in 0..leaves_num/2 {
            let leaf = get_random_field_element(i as u64);
            mht_leaves.push(leaf);
            append_leaf_to_ginger_mht(&mut mht, &leaf);
        }
        for _ in leaves_num/2..leaves_num {
            mht_leaves.push(FieldElement::zero());
        }

        // Compute the root
        finalize_ginger_mht_in_place(&mut mht);
        let mht_root = get_ginger_mht_root(&mht).expect("Tree must've been finalized");

        for i in 0..leaves_num {

            //Create and verify merkle paths for each leaf
            let path = get_ginger_mht_path(&mht, i as u64).unwrap();
            assert!(verify_ginger_merkle_path_without_length_check(&path,&mht_leaves[i], &mht_root).unwrap());

            // Check leaf index is the correct one
            assert_eq!(i as u64, get_leaf_index_from_path(&path));

            if i == 0 { // leftmost check
                assert!(is_path_leftmost(&path));
            }
            else if i == (leaves_num / 2) - 1 { // non-empty rightmost check
                assert!(is_path_non_empty_rightmost(&path));
            }
            else if i == leaves_num - 1 { //rightmost check
                assert!(is_path_rightmost(&path));
            }
            else { // Other cases check
                assert!(!is_path_leftmost(&path));
                assert!(!is_path_rightmost(&path));

                if i < (leaves_num / 2) - 1 {
                    assert!(!is_path_non_empty_rightmost(&path));
                }
            }

            // Serialization/deserialization test
            let path_size = get_path_size_in_bytes(&path);
            let mut path_serialized = vec![0u8; path_size];
            serialize_to_buffer(&path, &mut path_serialized).unwrap();
            let path_deserialized: GingerMHTPath = deserialize_from_buffer(&path_serialized).unwrap();
            assert_eq!(path, path_deserialized);
        }
    }

    #[test]
    fn sample_restore_merkle_tree() {
        let expected_root = FieldElement::new(
            BigInteger768([
                1174313500572535251,
                11989340445607088007,
                12453165802583165309,
                6869334689845037123,
                18071747287931669646,
                10010741666663785511,
                17335522832723564810,
                8102968406317429938,
                11258756029259070139,
                11585029297630923139,
                10229262840520193915,
                10238382938508
            ]));

        let height = 5;

        // create a persistent smt in a separate scope
        {
            let mut smt = get_ginger_smt(
                height,
                "./db_leaves_persistency_test_info",
            ).unwrap();

            //Insert some leaves in the tree
            let leaves = vec![FieldElement::from(1u16), FieldElement::from(2u16)];
            add_leaf_to_ginger_smt(&mut smt, &leaves[0], 0);
            add_leaf_to_ginger_smt(&mut smt, &leaves[1], 9);
            remove_leaf_from_ginger_smt(&mut smt, 0);

            // smt gets dropped but its info should be saved
        }

        // files and directories should have been created
        assert!(Path::new("./db_leaves_persistency_test_info").exists());

        // create a non-persistent smt in another scope by restoring the previous one
        {
            let mut smt = get_ginger_smt(
                height,
                "./db_leaves_persistency_test_info",
            ).unwrap();

            // insert other leaves
            let leaves = vec![FieldElement::from(10u16), FieldElement::from(3u16)];
            add_leaf_to_ginger_smt(&mut smt, &leaves[0], 16);
            add_leaf_to_ginger_smt(&mut smt, &leaves[1], 29);
            remove_leaf_from_ginger_smt(&mut smt, 16);

            // if truly state has been kept, then the equality below must pass, since `root` was
            // computed in one go with another smt
            assert_eq!(expected_root, get_ginger_smt_root(&smt));

            //Set the persistency of the tree to false so that the tree gets dropped
            set_ginger_smt_persistency(&mut smt, false);

            // smt gets dropped and state and dbs are deleted
        }

        // files and directories should have been deleted
        assert!(!Path::new("./db_leaves_persistency_test_info").exists());
    }

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