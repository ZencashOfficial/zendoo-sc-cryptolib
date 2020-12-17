pub mod constraints;

use primitives::signature::schnorr::field_based_schnorr::FieldBasedSchnorrPk;
use algebra::{PrimeField, Group};
use r1cs_core::ToConstraintField;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath, FieldBasedMerkleTreePath, FieldBasedSignatureScheme};
use serde::{Serialize, Deserialize};

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct BaseCoinBox<
    F: PrimeField,
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