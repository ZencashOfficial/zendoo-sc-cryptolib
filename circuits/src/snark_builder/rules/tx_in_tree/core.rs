use algebra::{PrimeField, ProjectiveCurve, ToConstraintField};
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use crate::{
    base_tx_circuit::{
        gadgets::{
            transaction::CoreTransactionGadget,
            transition::MerkleTreeTransitionGadget,
        },
        constants::TransactionParameters
    },
    rules::tx_in_tree::TxInTreeRule,
};
use r1cs_std::{
    alloc::{AllocGadget, ConstantGadget},
    bits::boolean::Boolean,
    groups::GroupGadget,
    fields::fp::FpGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    eq::EqGadget
};
use r1cs_crypto::{crh::FieldBasedHashGadget, merkle_tree::field_based_mht::FieldBasedBinaryMerkleTreePathGadget, FieldHasherGadget};
use r1cs_core::{ConstraintSystem, SynthesisError};
use std::marker::PhantomData;

pub struct CoreTxInTreeRuleProverData<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    /// Merkle Path to the leaf where tx will be placed in the Applied Payment Transactions Merkle Tree
    pub(crate) txs_tree_tx_path:         FieldBasedBinaryMHTPath<MHTP>,

    /// Applied Payment Transactions Merkle Tree Root before applying tx
    pub(crate) prev_txs_tree_root:       Option<MHTP::Data>,

    /// Applied Payment Transactions Merkle Tree Root after applying `tx_pay`
    pub(crate) new_txs_tree_root:        Option<MHTP::Data>,
}

impl<ConstraintF, H, MHTP> CoreTxInTreeRuleProverData<ConstraintF, H, MHTP>
where
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    pub fn new(
        path:         FieldBasedBinaryMHTPath<MHTP>,
        prev_tx_root: Option<ConstraintF>,
        next_tx_root: Option<ConstraintF>
    ) -> Self {
        Self {
            txs_tree_tx_path: path,
            prev_txs_tree_root: prev_tx_root,
            new_txs_tree_root: next_tx_root,
        }
    }
}

pub struct CoreTxInTreeRule<
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

impl<ConstraintF, G, GG, H, HG, MHTP, TXP> CoreTxInTreeRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
where
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: TransactionParameters,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    pub fn new<CS: ConstraintSystem<ConstraintF>>() -> Self
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

    pub fn enforce<CS: ConstraintSystem<ConstraintF>>(
        mut cs:            CS,
        prover_data:       CoreTxInTreeRuleProverData<ConstraintF, H, MHTP>,
        tx_gadget:         &<Self as TxInTreeRule<ConstraintF, H, HG, MHTP>>::TransactionGadget,
    ) -> Result<Self, SynthesisError>
    {
        // Alloc `txs_tree_tx_path`
        let txs_tree_tx_path_g = <Self as TxInTreeRule<ConstraintF, H, HG, MHTP>>::MerklePathGadget::alloc(
            cs.ns(|| "alloc txs_tree_tx_path"),
            || Ok(&prover_data.txs_tree_tx_path)
        )?;

        // Alloc Applyied Payment Transaction Tree roots
        let prev_txs_tree_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input prev_txs_tree_root"),
            || prover_data.prev_txs_tree_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let new_txs_tree_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input next_txs_tree_root"),
            || prover_data.new_txs_tree_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let new_instance = Self {
            _group: PhantomData,
            _group_gadget: PhantomData,
            _hash: PhantomData,
            _hash_gadget: PhantomData,
            _tx_params: PhantomData,
            _tree_params: PhantomData
        };

        new_instance.enforce_rule(
            cs.ns(|| "enforce tx in tree rule"),
            tx_gadget,
            txs_tree_tx_path_g,
            prev_txs_tree_root_g,
            new_txs_tree_root_g
        )?;

        Ok(new_instance)
    }
}


impl<ConstraintF, G, GG, H, HG, MHTP, TXP> TxInTreeRule<ConstraintF, H, HG, MHTP>
for CoreTxInTreeRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: TransactionParameters,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    type MerklePathGadget = FieldBasedBinaryMerkleTreePathGadget<MHTP, HG, ConstraintF>;
    type TransactionGadget = CoreTransactionGadget<ConstraintF, G, GG, H, HG, TXP>;

    #[inline]
    fn enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        tx_gadget:      &Self::TransactionGadget,
        tx_path_g:      Self::MerklePathGadget,
        prev_root_g:    FpGadget<ConstraintF>,
        next_root_g:    FpGadget<ConstraintF>,
    ) -> Result<(), SynthesisError> {

        // Enforce tx_hash
        let tx_hash_g = tx_gadget.enforce_hash(
            cs.ns(|| "enforce tx_hash"),
            None
        )?;

        // Check correct update of Applied Payment Transactions Merkle Tree
        //    a) Check that the leaf corresponding to `txs_tree_tx_path` is NULL in `prev_txs_tree_root`
        //    b) Check that the leaf corresponding to `txs_tree_tx_path` is H(tx_pay) in `new_txs_tree_root`

        // Enforce appending tx_hash to txs_tree
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &MHTP::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        let new_txs_tree_root_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_replacement(
            cs.ns(|| "enforce tx_hash insertion in block_txs_tree"),
            &prev_root_g,
            &tx_path_g,
            &null_leaf,
            &tx_hash_g,
            &Boolean::constant(true)
        )?;

        // Enforce next_txs_tree_root is correct
        new_txs_tree_root_g.enforce_equal(cs.ns(|| "enforce next_txs_tree_root"), &next_root_g)?;

        Ok(())
    }
}