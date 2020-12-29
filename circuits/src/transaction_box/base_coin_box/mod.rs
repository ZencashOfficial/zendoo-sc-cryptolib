pub mod constraints;

use primitives::signature::schnorr::field_based_schnorr::FieldBasedSchnorrPk;
use algebra::{Field, Group};
use r1cs_core::ToConstraintField;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath, FieldBasedMerkleTreePath, FieldBasedSignatureScheme};
use serde::{Serialize, Deserialize};
use crate::transaction_box::TransactionBox;

// TODO: GINGER: Deserialize is not defined for Field and PrimeField
// TODO: GINGER: the trait `std::default::Default` is not implemented for `<P as primitives::FieldBasedMerkleTreeParameters>::H`
// TODO: GINGER: the trait `std::clone::Clone` is not implemented for `<P as primitives::FieldBasedMerkleTreeParameters>::H`
// #[derive(Clone, Default, Serialize, Deserialize)]
#[derive(Clone, Default, Serialize)]
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