pub mod constraints;

use algebra::Field;
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath, FieldBasedSignatureScheme};
use serde::{Serialize, Deserialize};
use crate::transaction_box::TransactionBox;

#[derive(Derivative)]
#[derivative(
    Clone(bound = ""),
    Default(bound = ""),
)]
#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "F: Field"))]
pub struct BaseCoinBox<
    F: Field,
    S: FieldBasedSignatureScheme<Data = F>,
    P: FieldBasedMerkleTreeParameters<Data = F>,
>
{
    pub amount: u64,
    pub pk: S::PublicKey,
    pub nonce: u64,
    pub id: F,
    pub custom_hash: F,
    pub mst_path: FieldBasedBinaryMHTPath<P>,
    pub bvt_path: FieldBasedBinaryMHTPath<P>,
    pub bvt_leaf: F,
}

impl<F, S, P> TransactionBox for BaseCoinBox<F, S, P>
where
    F: Field,
    S: FieldBasedSignatureScheme<Data = F>,
    P: FieldBasedMerkleTreeParameters<Data = F> {}