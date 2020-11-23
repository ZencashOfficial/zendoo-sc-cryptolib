use algebra::PrimeField;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedMerkleTreePath};
use r1cs_std::alloc::AllocGadget;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::bits::boolean::Boolean;
use r1cs_std::fields::fp::FpGadget;

pub mod core;

pub trait TxTreeStateTransitionRule<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    P: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    /// TODO: Would be enough to specify MerklePathGadget if we had a gadget trait
    ///       MerklePaths in Ginger.
    type MerklePath:            FieldBasedMerkleTreePath<H=H, Parameters=P>;
    type MerklePathGadget:      AllocGadget<Self::MerklePath, ConstraintF>;

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
