use crate::transaction_box::base_coin_box::constraints::BaseCoinBoxGadget;
use algebra::PrimeField;
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedHash, FieldBasedSignatureScheme, FieldBasedMerkleTreePath};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget, FieldBasedMerkleTreePathGadget};

pub struct ZenBoxGadget<
    ConstraintF: PrimeField,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
>
{
    pub coin_box: BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    // Other fields ?
}

//TODO: Impl TransactionBoxGadget also for ZenBoxGadget (means implementing AllocGadget, HardcodeGadget and EqGadget)

pub struct InputZenBoxGadget<
    ConstraintF: PrimeField,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
> {
    pub zen_box: ZenBoxGadget<ConstraintF, P, H, HG, S, SG>,
    pub sig:     SG::SignatureGadget,
}

pub type OutputZenBoxGadget<ConstraintF, P, H, HG, S, SG> = ZenBoxGadget<ConstraintF, P, H, HG, S, SG>;