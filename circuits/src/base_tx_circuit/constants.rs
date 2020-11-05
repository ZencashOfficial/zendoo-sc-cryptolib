use algebra::{PrimeField, ToConstraintField, ProjectiveCurve};

use crate::base_tx_circuit::primitives::transaction::{
    InputCoinBox, OutputCoinBox,
};

pub trait BaseTransactionParameters<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> {
    const PADDING_INPUT_BOX: InputCoinBox<F, G>;
    const PADDING_OUTPUT_BOX: OutputCoinBox<F, G>;
}