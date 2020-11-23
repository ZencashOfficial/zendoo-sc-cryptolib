use algebra::PrimeField;
use r1cs_std::alloc::AllocGadget;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::bits::boolean::Boolean;

pub mod core;

///TODO: For the moment we assume, for this rule, that the tx already contains all the data required
///      to prove valid signatures on it (e.g. the data to be signed, the signatures and the public keys).
pub trait TxSignatureRule<ConstraintF: PrimeField> {

    type Transaction;
    type TransactionGadget:     AllocGadget<Self::Transaction, ConstraintF>;

    fn enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs: CS,
        tx_gadget:      &Self::TransactionGadget,
    ) -> Result<(), SynthesisError> {
        self.conditionally_enforce_rule(cs, tx_gadget, &Boolean::constant(true) )
    }

    fn conditionally_enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs: CS,
        tx_gadget:      &Self::TransactionGadget,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>;
}