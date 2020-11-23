use algebra::PrimeField;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldHasher, FieldBasedMerkleTreePath};
use r1cs_crypto::FieldBasedHashGadget;
use r1cs_std::alloc::AllocGadget;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::fields::fp::FpGadget;

pub mod core;

/// Generic trait holding data and SNARK logic required to enforce belonging of a Transaction
/// to a Merkle Tree
pub trait TxInTreeRule<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF>,
    P: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>: Sized
{
    /// TODO: Would be enough to specify MerklePathGadget if we had a gadget trait
    ///       MerklePaths in Ginger.
    type MerklePath: FieldBasedMerkleTreePath<H=H, Parameters=P>;
    type MerklePathGadget: AllocGadget<Self::MerklePath, ConstraintF>;

    /// TODO: Would be enough to specify TransactionGadget if TransactionGadget implemented
    ///       the FieldHasherGadget trait.
    type Transaction: FieldHasher<ConstraintF, H>;
    type TransactionGadget: AllocGadget<Self::Transaction, ConstraintF>;

    fn enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs:             CS,
        tx_g:           &Self::TransactionGadget,
        tx_path_g:      Self::MerklePathGadget,
        prev_root_g:    FpGadget<ConstraintF>,
        next_root_g:    FpGadget<ConstraintF>,
    ) -> Result<(), SynthesisError>;
}