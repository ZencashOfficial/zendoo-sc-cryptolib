use crate::TransactionBox;
use algebra::Field;
use r1cs_std::alloc::{AllocGadget, ConstantGadget};
use r1cs_std::eq::EqGadget;
use r1cs_core::ConstraintSystem;

pub trait TransactionBoxGadget<ConstraintF: Field, B: TransactionBox>:
    // We need to be able to allocate a Box in the circuit
    AllocGadget<B, ConstraintF> +
    // May be needed to hardcode a phantom box in the circuit
    ConstantGadget<B, ConstraintF> +
    // We can compare self with another self containing a phantom box in order to
    // enforce a Boolean to be True if they are not equals, to False otherwise.
    EqGadget<ConstraintF> +
    Eq + PartialEq
{
    fn get_phantom<CS: ConstraintSystem<ConstraintF>>(cs: CS) -> Self {
        let phantom_box = B::default();
        <Self as ConstantGadget<B, ConstraintF>>::from_value(cs, &phantom_box)
    }
}