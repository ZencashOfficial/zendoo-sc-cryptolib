use crate::transaction_box::base_coin_box::constraints::BaseCoinBoxGadget;
use algebra::Field;
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedHash, FieldBasedSignatureScheme, FieldBasedMerkleTreePath};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget, FieldBasedMerkleTreePathGadget};

pub struct ZenBoxGadget<
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
    MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
>
{
    pub coin_box: BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    // Other fields
}

pub struct InputZenBoxGadget<
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
    MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
> {
    pub zen_box: ZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>,
    pub sig:     SG::SignatureGadget,
}

pub type OutputZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> = ZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>;