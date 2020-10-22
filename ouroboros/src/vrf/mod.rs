use algebra::curves::mnt6753::G1Projective as MNT6G1Projective;
//use algebra::curves::mnt6753::G1Affine as MNT6G1Affine;
use algebra::fields::mnt4753::{Fq as Fs, Fr as Fr};
use primitives::{crh::{
    MNT4PoseidonHash,
    bowe_hopwood::{
        BoweHopwoodPedersenCRH, BoweHopwoodPedersenParameters,
    },
    pedersen::PedersenWindow,
}, vrf::{
    FieldBasedVrf,
    ecvrf::{
        FieldBasedEcVrf, FieldBasedEcVrfProof, FieldBasedEcVrfPk,
    },
}};
use rand::rngs::OsRng;

#[derive(Clone)]
struct TestWindow {}
impl PedersenWindow for TestWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 2;
}

type GroupHash = BoweHopwoodPedersenCRH<MNT6G1Projective, TestWindow>;
type GroupHashParameters = BoweHopwoodPedersenParameters<MNT6G1Projective>;
type EcVrfScheme = FieldBasedEcVrf<Fr, MNT6G1Projective, MNT4PoseidonHash, GroupHash>;
type EcVrfProof = FieldBasedEcVrfProof<Fr, MNT6G1Projective>;
type EcVrfPk = FieldBasedEcVrfPk<MNT6G1Projective>;

pub fn ouroboros_create_proof
(
    pp: GroupHashParameters,
    epoch_randomness: Fr,
    _slot_number: u32,
    pk: EcVrfPk,
    sk: Fs,
    _forger_stake: u64,
    _total_forgers_stake: u64
) -> Option<(EcVrfProof, EcVrfProof)> {

    //Example calling code
    let rng = &mut OsRng;
    match EcVrfScheme::prove(rng, &pp, &pk, &sk, &[epoch_randomness]) {
        Ok(proof) => Some((proof.clone(), proof)),
        _ => None,
    }
}

pub fn ouroboros_check_proof
(
    pp: GroupHashParameters,
    proof: (EcVrfProof, EcVrfProof),
    epoch_randomness: Fr,
    _slot_number: u32,
    forger_pk: EcVrfPk, //Or MNT6G1Affine and you convert into projective by calling pk.into_projective() inside the function
    _forger_stake: u64,
    _total_forgers_stake: u64,

) -> Option<(Fr, Fr)> {
    //Example calling code
    match (
        EcVrfScheme::proof_to_hash(&pp, &forger_pk, &[epoch_randomness], &proof.0),
        EcVrfScheme::proof_to_hash(&pp, &forger_pk, &[epoch_randomness], &proof.1),
        )
    {
        (Ok(o1), Ok(o2)) => Some((o1, o2)),
        _ => None,
    }
}

/*
// NOTE: To simplify I put all the concrete types and didn't templatize anything. Actually this could
// be easily templatized, and when calling the functions passing values of the concrete types. The
// templatized version of the above functions looks like this:

pub fn ouroboros_create_proof_templatized<S: FieldBasedVrf>
(
    _pp: S::GHParams,
    _epoch_randomness: S::Data,
    _slot_number: u32,
    _pk: S::PublicKey,
    _forger_stake: u64,
    _total_forgers_stake: u64
) -> Option<(S::Proof, S::Proof)> {unimplemented!()}

pub fn ouroboros_check_proof_templatized<S: FieldBasedVrf>
(
    _pp: S::GHParams,
    _proof: (S::Proof, S::Proof),
    _epoch_randomness: S::Data,
    _slot_number: u32,
    _forger_pk: S::PublicKey,
    _forger_stake: u64,
    _total_forgers_stake: u64,

) -> Option<(S::Data, S::Data)> {unimplemented!()}
*/