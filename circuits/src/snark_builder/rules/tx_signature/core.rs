use algebra::{PrimeField, ProjectiveCurve, ToConstraintField};
use r1cs_std::groups::GroupGadget;
use r1cs_std::to_field_gadget_vec::ToConstraintFieldGadget;
use r1cs_std::fields::fp::FpGadget;
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters};
use r1cs_crypto::FieldBasedHashGadget;
use crate::base_tx_circuit::constants::TransactionParameters;
use std::marker::PhantomData;
use r1cs_core::{ConstraintSystem, SynthesisError};
use crate::snark_builder::rules::tx_signature::TxSignatureRule;
use crate::base_tx_circuit::base_tx_primitives::transaction::CoreTransaction;
use crate::base_tx_circuit::gadgets::transaction::CoreTransactionGadget;
use r1cs_std::bits::boolean::Boolean;

pub struct CoreTxSignatureRule<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: TransactionParameters,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    _group:             PhantomData<G>,
    _group_gadget:      PhantomData<GG>,
    _hash:              PhantomData<H>,
    _hash_gadget:       PhantomData<HG>,
    _tx_params:         PhantomData<TXP>,
    _tree_params:       PhantomData<MHTP>
}

impl<ConstraintF, G, GG, H, HG, MHTP, TXP> CoreTxSignatureRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: TransactionParameters,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    pub fn new() -> Self
    {
        Self {
            _group: PhantomData,
            _group_gadget: PhantomData,
            _hash: PhantomData,
            _hash_gadget: PhantomData,
            _tx_params: PhantomData,
            _tree_params: PhantomData
        }
    }
}

impl<ConstraintF, G, GG, H, HG, MHTP, TXP> TxSignatureRule<ConstraintF>
for CoreTxSignatureRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: TransactionParameters,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    type Transaction = CoreTransaction<ConstraintF, G, H, TXP>;
    type TransactionGadget = CoreTransactionGadget<ConstraintF, G, GG, H, HG, TXP>;

    fn conditionally_enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        tx_gadget: &Self::TransactionGadget,
        should_enforce: &Boolean
    ) -> Result<(), SynthesisError>
    {
        tx_gadget.conditionally_verify(
            cs.ns(|| "verify input boxes signatures"),
            should_enforce
        )
    }
}