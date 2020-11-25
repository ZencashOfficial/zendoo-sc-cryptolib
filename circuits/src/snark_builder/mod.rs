pub mod rules;

use algebra::PrimeField;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters};
use r1cs_crypto::FieldBasedHashGadget;
use crate::snark_builder::rules::{
    tx_signature::TxSignatureRule, tx_in_tree::TxInTreeRule
};
use crate::snark_builder::rules::tx_state_transition::TxTreeStateTransitionRule;
use r1cs_core::ConstraintSynthesizer;

pub trait TransactionCircuit<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>: ConstraintSynthesizer<ConstraintF>
{
    type InTreeRule:    TxInTreeRule<ConstraintF, H, HG, MHTP>;
    type SignatureRule: TxSignatureRule<ConstraintF>;
}

pub trait CoinTransactionCircuit<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>: TransactionCircuit<ConstraintF, H, HG, MHTP>
{
    type StateUpdateRule:   TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>;
    type BVTUpdateRule:     TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>;
}