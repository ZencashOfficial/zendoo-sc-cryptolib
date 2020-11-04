use algebra::{PrimeField, ToConstraintField, ProjectiveCurve};

use crate::base_tx_circuit::primitives::transaction::{
    InputBox, OutputBox,
};

/// Maybe it's enough to use just one NoncedBox and a FieldBasedSchnorrSignature ?
pub trait BaseTransactionParameters<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> {
    const PADDING_INPUT_BOX: InputBox<F, G>;
    const PADDING_OUTPUT_BOX: OutputBox<F, G>;
}