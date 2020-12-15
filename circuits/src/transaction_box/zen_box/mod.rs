use crate::transaction_box::base_coin_box::BaseCoinBox;
use algebra::PrimeField;
use primitives::{FieldBasedSignatureScheme, FieldBasedMerkleTreePath};

pub mod constraints;

pub struct ZenBox<
    F: PrimeField,
    S: FieldBasedSignatureScheme<Data = F>,
    MHTP: FieldBasedMerkleTreePath
>
{
    coin_box: BaseCoinBox<F, S, MHTP>
    // Other fields
}

pub struct InputZenBox<
    F: PrimeField,
    S: FieldBasedSignatureScheme<Data = F>,
    MHTP: FieldBasedMerkleTreePath
>
{
    zen_box: ZenBox<F, S, MHTP>,
    sig:     S::Signature,
}

pub type OutputZenBox<F, S, MHTP> = ZenBox<F, S, MHTP>;