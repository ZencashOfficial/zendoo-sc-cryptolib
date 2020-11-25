use algebra::PrimeField;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use r1cs_std::alloc::AllocGadget;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::bits::boolean::Boolean;
use r1cs_std::fields::fp::FpGadget;
use r1cs_crypto::{FieldBasedMerkleTreePathGadget, FieldBasedHashGadget};

pub mod core;

pub trait TxTreeStateTransitionRule<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF>,
    P: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    type MerklePathGadget:      FieldBasedMerkleTreePathGadget<FieldBasedBinaryMHTPath<P>, H, HG, ConstraintF>;

    type Transaction;
    type TransactionGadget:     AllocGadget<Self::Transaction, ConstraintF>;

    fn enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs:                      CS,
        tx_gadget:               &Self::TransactionGadget,
        path_to_input_gs:        Vec<Self::MerklePathGadget>,
        path_to_output_gs:       Vec<Self::MerklePathGadget>,
        prev_root:               FpGadget<ConstraintF>,
        next_root:               FpGadget<ConstraintF>,
    ) -> Result<(), SynthesisError>
    {
        self.conditionally_enforce_rule(
            cs,
            tx_gadget,
            path_to_input_gs,
            path_to_output_gs,
            prev_root,
            next_root,
            &Boolean::Constant(true)
        )
    }

    fn conditionally_enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs:                      CS,
        tx_gadget:               &Self::TransactionGadget,
        path_to_input_gs:        Vec<Self::MerklePathGadget>,
        path_to_output_gs:       Vec<Self::MerklePathGadget>,
        prev_root:               FpGadget<ConstraintF>,
        next_root:               FpGadget<ConstraintF>,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>;
}
