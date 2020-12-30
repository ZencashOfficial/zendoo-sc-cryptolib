use crate::transaction_box::base_coin_box::BaseCoinBox;
use algebra::PrimeField;
use primitives::{FieldBasedSignatureScheme, FieldBasedMerkleTreeParameters};

pub mod constraints;

pub struct ZenBox<
    F: PrimeField,
    S: FieldBasedSignatureScheme<Data = F>,
    P: FieldBasedMerkleTreeParameters<Data = F>,
>
{
    coin_box: BaseCoinBox<F, S, P>
    // Other fields ?
}

pub struct InputZenBox<
    F: PrimeField,
    S: FieldBasedSignatureScheme<Data = F>,
    P: FieldBasedMerkleTreeParameters<Data = F>,
>
{
    zen_box: ZenBox<F, S, P>,
    sig:     S::Signature,
}

pub type OutputZenBox<F, S, P> = ZenBox<F, S, P>;