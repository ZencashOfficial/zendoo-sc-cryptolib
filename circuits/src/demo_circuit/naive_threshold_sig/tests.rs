use algebra::{
    BigInteger768,
    fields::mnt4753::Fr as MNT4Fr,
    curves::mnt6753::G1Projective as MNT6G1Projective,
    Field, PrimeField, ToBits, ProjectiveCurve,
};

use primitives::{
    signature::{
        schnorr::field_based_schnorr::{
            FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme,
            FieldBasedSchnorrPk,
        },
        FieldBasedSignatureScheme,
    },
    crh::{FieldBasedHash, MNT4PoseidonHash},
};
use r1cs_crypto::{
    signature::{
        schnorr::field_based_schnorr::{
            FieldBasedSchnorrSigGadget, FieldBasedSchnorrSigVerificationGadget,
            FieldBasedSchnorrPkGadget,
        },
        FieldBasedSigGadget,
    },
    crh::{MNT4PoseidonHashGadget, FieldBasedHashGadget}
};

use r1cs_std::{
    instantiated::mnt6_753::G1Gadget as MNT6G1Gadget,
    fields::{
        fp::FpGadget, FieldGadget,
    },
    alloc::AllocGadget,
    bits::{
        boolean::Boolean, FromBitsGadget,
    },
    eq::EqGadget, test_constraint_system::TestConstraintSystem,
};

use r1cs_core::ConstraintSystem;
use crate::constants::NaiveThresholdSigParams;

use rand::{
    Rng, rngs::OsRng
};

use lazy_static::*;

lazy_static! {
    pub static ref NULL_CONST: NaiveThresholdSigParams = { NaiveThresholdSigParams::new() };
}

//Sig types
type SchnorrSig = FieldBasedSchnorrSignatureScheme<MNT4Fr, MNT6G1Projective, MNT4PoseidonHash>;
type SchnorrSigGadget = FieldBasedSchnorrSigGadget<MNT4Fr, MNT6G1Projective>;
type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
    MNT4Fr, MNT6G1Projective, MNT6G1Gadget, MNT4PoseidonHash, MNT4PoseidonHashGadget
>;
type SchnorrPk = FieldBasedSchnorrPk<MNT6G1Projective>;
type SchnorrPkGadget = FieldBasedSchnorrPkGadget<MNT4Fr, MNT6G1Projective, MNT6G1Gadget>;

//Field types
type MNT4FrGadget = FpGadget<MNT4Fr>;

struct NaiveTresholdSignatureTest{

    //Witnesses
    pks:                      Vec<SchnorrPk>,
    sigs:                     Vec<FieldBasedSchnorrSignature<MNT4Fr, MNT6G1Projective>>,
    threshold:                MNT4Fr,
    b:                        Vec<bool>,
    end_epoch_mc_b_hash:      MNT4Fr,
    prev_end_epoch_mc_b_hash: MNT4Fr,
    mr_bt:                    MNT4Fr,

    //Public inputs
    aggregated_input:         MNT4Fr,

    //Other
    max_pks:                  usize,
}


fn generate_inputs
(
    max_pks:                  usize,
    valid_sigs:               usize,
    threshold:                usize,
    wrong_pks_threshold_hash: bool,
    wrong_wcert_sysdata_hash: bool,
) -> NaiveTresholdSignatureTest
{
    //Istantiate rng
    let mut rng = OsRng::default();
    let mut h = MNT4PoseidonHash::init(None);

    //Generate message to sign
    let mr_bt: MNT4Fr = rng.gen();
    let prev_end_epoch_mc_b_hash: MNT4Fr = rng.gen();
    let end_epoch_mc_b_hash: MNT4Fr = rng.gen();
    let message = h
        .update(mr_bt)
        .update(prev_end_epoch_mc_b_hash)
        .update(end_epoch_mc_b_hash)
        .finalize();
    //Generate another random message used to simulate a non-valid signature
    let invalid_message: MNT4Fr = rng.gen();

    let mut pks = vec![];
    let mut sigs = vec![];

    for _ in 0..valid_sigs {
        let (pk, sk) = SchnorrSig::keygen(&mut rng);
        let sig = SchnorrSig::sign(&mut rng, &pk, &sk, &[message]).unwrap();
        pks.push(pk);
        sigs.push(sig);
    }

    for _ in 0..(max_pks-valid_sigs){
        //Sample a random boolean and decide if generating a non valid signature or a null one
        let generate_null: bool = rng.gen();
        let (pk, sig) = if generate_null {
            (NULL_CONST.null_pk, NULL_CONST.null_sig)
        } else {
            let (pk, sk) = SchnorrSig::keygen(&mut rng);
            let sig = SchnorrSig::sign(&mut rng, &pk, &sk, &[invalid_message]).unwrap();
            (pk, sig)
        };
        pks.push(pk);
        sigs.push(sig);
    }

    //Generate b
    let t_field = MNT4Fr::from_repr(BigInteger768::from(threshold as u64));
    let valid_field = MNT4Fr::from_repr(BigInteger768::from(valid_sigs as u64));
    let b_field = valid_field - &t_field;
    let b_bool = {
        let log_max_pks = (max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
        let to_skip = MNT4Fr::size_in_bits() - (log_max_pks + 1);
        b_field.write_bits()[to_skip..].to_vec()
    };

    //Compute pks_threshold_hash
    h.reset(None);
    pks.iter().for_each(|pk| { h.update(pk.0.into_affine().x); });
    let pks_hash = h.finalize();
    let pks_threshold_hash = if !wrong_pks_threshold_hash {
        h
            .reset(None)
            .update(pks_hash)
            .update(t_field)
            .finalize()
    } else {
        rng.gen()
    };

    //Compute wcert_sysdata_hash
    let wcert_sysdata_hash = if !wrong_wcert_sysdata_hash {
        h
            .reset(None)
            .update(valid_field)
            .update(mr_bt)
            .update(prev_end_epoch_mc_b_hash)
            .update(end_epoch_mc_b_hash)
            .finalize()
    } else {
        rng.gen()
    };

    // Compute aggregated input
    let aggregated_input = h
        .reset(None)
        .update(pks_threshold_hash)
        .update(wcert_sysdata_hash)
        .finalize();

    //Create instance of the circuit
    NaiveTresholdSignatureTest {
        pks,
        sigs,
        threshold: t_field,
        b: b_bool,
        end_epoch_mc_b_hash,
        prev_end_epoch_mc_b_hash,
        mr_bt,
        aggregated_input,
        max_pks,
    }
}

fn generate_constraints(
    c: NaiveTresholdSignatureTest,
    mut cs: TestConstraintSystem<MNT4Fr>,
) -> bool
{
    //Internal checks
    let log_max_pks = (c.max_pks.next_power_of_two() as u64).trailing_zeros() as usize;
    assert_eq!(c.max_pks, c.pks.len());
    assert_eq!(c.max_pks, c.sigs.len());
    assert_eq!(log_max_pks + 1, c.b.len());

    //Check pks are consistent with c.hash_commitment

    //Allocate public keys as witnesses
    let mut pks_g = Vec::with_capacity(c.max_pks);

    for (i, pk) in c.pks.iter().enumerate() {
        // It's safe to not perform any check when allocating the pks,
        // considering that the pks are hashed, so they should be public
        // at some point, therefore verifiable by everyone.
        let pk_g = SchnorrPkGadget::alloc_without_check(
            cs.ns(|| format!("alloc_pk_{}", i)),
            || Ok(pk)
        ).unwrap();
        pks_g.push(pk_g);
    }

    //Check pks
    let mut pks_threshold_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "hash public keys"),
        pks_g.iter().map(|pk| pk.pk.x.clone()).collect::<Vec<_>>().as_slice(),
    ).unwrap();

    //Allocate threshold as witness
    let t_g = MNT4FrGadget::alloc(
        cs.ns(|| "alloc threshold"),
        || Ok(c.threshold)
    ).unwrap();

    //Check hash commitment
    pks_threshold_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "H(H(pks), threshold)"),
        &[pks_threshold_hash_g, t_g.clone()],
    ).unwrap();

    //Check signatures

    //Reconstruct message as H(MR(BT), BH(Bi-1), BH(Bi))

    let mr_bt_g = MNT4FrGadget::alloc(
        cs.ns(|| "alloc mr_bt"),
        || Ok(c.mr_bt)
    ).unwrap();

    let prev_end_epoch_mc_block_hash_g = MNT4FrGadget::alloc(
        cs.ns(|| "alloc prev_end_epoch_mc_block_hash"),
        || Ok(c.prev_end_epoch_mc_b_hash)
    ).unwrap();

    let end_epoch_mc_block_hash_g = MNT4FrGadget::alloc(
        cs.ns(|| "alloc end_epoch_mc_block_hash"),
        || Ok(c.end_epoch_mc_b_hash)
    ).unwrap();

    let message_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "H(MR(BT), H(Bi-1), H(Bi))"),
        &[mr_bt_g.clone(), prev_end_epoch_mc_block_hash_g.clone(), end_epoch_mc_block_hash_g.clone()],
    ).unwrap();

    let mut sigs_g = Vec::with_capacity(c.max_pks);

    //Allocate signatures as witnesses
    for (i, sig) in c.sigs.iter().enumerate() {
        let sig_g = SchnorrSigGadget::alloc(
            cs.ns(|| format!("alloc_sig_{}", i)),
            || Ok(sig)
        ).unwrap();
        sigs_g.push(sig_g);
    }

    let mut verdicts = Vec::with_capacity(c.max_pks);

    //Check signatures verification verdict on message
    for (i ,(pk_g, sig_g))
        in pks_g.iter().zip(sigs_g.iter()).enumerate() {

        let v = SchnorrVrfySigGadget::enforce_signature_verdict(
            cs.ns(|| format!("check_sig_verdict_{}", i)),
            pk_g,
            sig_g,
            &[message_g.clone()],
        ).unwrap();
        verdicts.push(v);
    }

    //Count valid signatures
    let mut valid_signatures = MNT4FrGadget::zero(cs.ns(|| "alloc valid signatures count")).unwrap();
    for (i, v) in verdicts.iter().enumerate() {
        valid_signatures = valid_signatures.conditionally_add_constant(
            cs.ns(|| format!("add_verdict_{}", i)),
            v,
            MNT4Fr::one(),
        ).unwrap();
    }

    //Enforce correct wcert_sysdata_hash
    let wcert_sysdata_hash_g = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "H(valid_signatures, MR(BT), BH(Bi-1), BH(Bi))"),
        &[valid_signatures.clone(), mr_bt_g, prev_end_epoch_mc_block_hash_g, end_epoch_mc_block_hash_g]
    ).unwrap();

    //Check pks_threshold_hash and wcert_sysdata_hash
    let expected_aggregated_input = MNT4FrGadget::alloc_input(
        cs.ns(|| "alloc aggregated input"),
        || Ok(c.aggregated_input)
    ).unwrap();

    let actual_aggregated_input = MNT4PoseidonHashGadget::check_evaluation_gadget(
        cs.ns(|| "H(pks_threshold_hash, wcert_sysdata_hash)"),
        &[pks_threshold_hash_g, wcert_sysdata_hash_g]
    ).unwrap();

    expected_aggregated_input.enforce_equal(
        cs.ns(|| "check aggregated input"),
        &actual_aggregated_input
    ).unwrap();


    //Alloc the b's as witnesses
    let mut bs_g = Vec::with_capacity(log_max_pks + 1);
    for (i, b) in c.b.iter().enumerate(){
        let b_g = Boolean::alloc(
            cs.ns(|| format!("alloc b_{}", i)),
            || Ok(b)
        ).unwrap();
        bs_g.push(b_g);
    }

    //Pack the b's into a field element
    let b_field = MNT4FrGadget::from_bits(
        cs.ns(|| "pack the b's into a field element"),
        bs_g.as_slice(),
    ).unwrap();

    //Enforce threshold
    valid_signatures
        .sub(cs.ns(|| "valid_signatures - threshold"), &t_g).unwrap()
        .enforce_equal(cs.ns(|| "threshold check"), &b_field).unwrap();

    if !cs.is_satisfied() {
        println!("**********Unsatisfied Constraints***********");
        println!("{:?}", cs.which_is_unsatisfied());
    }

    cs.is_satisfied()
}

#[test]
fn random_naive_threshold_sig_test() {
    let mut rng = OsRng::default();

    let n = 6;
    for t in 0..n + 1 {
        let v: usize = rng.gen_range(0, n + 1);
        let satisfiable = v >= t;

        println!("************THRESHOLD {}****************", t);
        println!("Valid signatures: {}", v);
        println!("CS satisfiable: {}", satisfiable);

        let c = generate_inputs(n, v, t, false, false);
        let cs = TestConstraintSystem::<MNT4Fr>::new();
        let is_satisfied = generate_constraints(c, cs);

        // The output must be false whenever the cs should be satisfiable
        // but it actually isn't, and viceversa. This behaviour can be
        // encoded with a XNOR.
        assert!(!(satisfiable ^ is_satisfied));
        println!("Ok!");
    }
}

#[test]
fn naive_threshold_sig_test_all_cases() {
    let mut rng = OsRng::default();
    let n = 6;

    println!("Test success case with v > t");
    let v = rng.gen_range(1, n);
    let t = rng.gen_range(0, v);
    let c = generate_inputs(n, v, t, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test success case with v == t");
    let v = rng.gen_range(1, n);
    let t = v;
    let c = generate_inputs(n, v, t, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case with v < t");
    let t = rng.gen_range(1, n);
    let v = rng.gen_range(0, t);
    let c = generate_inputs(n, v, t, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = t = 0");
    let c = generate_inputs(n, 0, 0, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = t = n");
    let c = generate_inputs(n, n, n, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test case v = n and t = 0");
    let c = generate_inputs(n, n, 0, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case v = 0 and t = n");
    let c = generate_inputs(n, 0, n, false, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case wrong pks_threshold_hash");
    let v = rng.gen_range(1, n);
    let t = rng.gen_range(0, v);
    let c = generate_inputs(n, v, t, true, false);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");

    println!("Test negative case wrong wcert_sysdata_hash");
    let v = rng.gen_range(1, n);
    let t = rng.gen_range(0, v);
    let c = generate_inputs(n, v, t, false, true);
    let cs = TestConstraintSystem::<MNT4Fr>::new();
    assert!(!generate_constraints(c, cs));
    println!("Ok !");
}