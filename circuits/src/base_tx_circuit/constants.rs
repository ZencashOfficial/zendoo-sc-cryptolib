use algebra::{PrimeField, ToConstraintField, ProjectiveCurve};

use crate::base_tx_circuit::base_tx_primitives::transaction::{
    InputCoinBox, OutputCoinBox,
};

pub trait TransactionParameters {
    const MAX_I_O_BOXES:    usize;
}

pub trait CoreTransactionParameters<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>>: TransactionParameters {
    const PADDING_INPUT_BOX: InputCoinBox<F, G>;
    const PADDING_OUTPUT_BOX: OutputCoinBox<F, G>;
}