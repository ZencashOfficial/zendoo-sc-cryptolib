pub mod gadgets;
pub mod base_tx_primitives;
pub mod constants;

use algebra::{PrimeField, ProjectiveCurve, ToConstraintField, fields::FpParameters};
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::AllocGadget,
    groups::GroupGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    fields::fp::FpGadget,
    eq::EqGadget,
    bits::boolean::Boolean
};
use r1cs_crypto::FieldBasedHashGadget;
use crate::base_tx_circuit::{
    base_tx_primitives::transaction::CoreTransaction,
    gadgets::transaction::CoreTransactionGadget,
    constants::CoreTransactionParameters,
};
use crate::snark_builder::rules::{
    tx_state_transition::core::{
        CoreTxMerkleTreeStateTransitionRule, CoreTxBVTStateTransitionRule,
        CoreTxMerkleTreeStateTransitionRuleProverData, CoreTxBVTStateTransitionRuleProverData
    },
    tx_in_tree::core::{CoreTxInTreeRuleProverData, CoreTxInTreeRule},
    tx_signature::{core::CoreTxSignatureRule, TxSignatureRule},
};
use crate::{TransactionCircuit, CoinTransactionCircuit};
use std::marker::PhantomData;
use crate::base_tx_circuit::constants::TransactionParameters;

/// Base proof of transition for a single payment transaction, able to contain more than on
/// input/output coin box. The approach is to sequentially enforce one input/output transition
/// at time in the transaction.
pub struct CoreTransactionCircuit<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: CoreTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    /// A transaction with `MAX_I_O_BOXES` coin box inputs and `MAX_I_O_BOXES`
    /// coin box outputs and the associated fee explicitly needed as public input to
    /// bring it up recursively in the proof tree, since it will be used in the block
    /// proof to enforce the forger's payment

    txs:                Vec<(CoreTransaction<ConstraintF, G, H, TXP>, Option<ConstraintF>)>,

    mst_rules:          Vec<Option<CoreTxMerkleTreeStateTransitionRuleProverData<ConstraintF, H, MHTP>>>,
    bvt_rules:          Vec<Option<CoreTxBVTStateTransitionRuleProverData<ConstraintF, H, MHTP>>>,
    tx_in_tree_rules:   Vec<Option<CoreTxInTreeRuleProverData<ConstraintF, H, MHTP>>>,

    /// Number of bits that are grouped to form a leaf of the Bit Vector Tree,
    /// expressed as a Field Element for simplicity.
    bv_tree_batch_size: usize,

    _group_gadget:      PhantomData<GG>,
    _hash_gadget:       PhantomData<HG>,
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> CoreTransactionCircuit<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: CoreTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    pub fn new(max_tx: usize) -> Self {
        Self {
            txs:                Vec::with_capacity(max_tx),
            mst_rules:          Vec::with_capacity(max_tx),
            bvt_rules:          Vec::with_capacity(max_tx),
            tx_in_tree_rules:   Vec::with_capacity(max_tx),
            bv_tree_batch_size: ConstraintF::Params::CAPACITY as usize,
            _group_gadget:      PhantomData,
            _hash_gadget:       PhantomData
        }
    }

    pub fn add_tx(
        &mut self,
        tx_pay:                   CoreTransaction<ConstraintF, G, H, TXP>,
        fee:                      Option<ConstraintF>,
        // For CoreTxInTreeRule
        txs_tree_tx_path:         FieldBasedBinaryMHTPath<MHTP>,
        prev_txs_tree_root:       Option<MHTP::Data>,
        new_txs_tree_root:        Option<MHTP::Data>,
        // For CoreTxMerkleTreeStateTransitionRule
        mst_paths_to_inputs:      Vec<FieldBasedBinaryMHTPath<MHTP>>,
        mst_paths_to_outputs:     Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_mst_root:            Option<MHTP::Data>,
        new_mst_root:             Option<MHTP::Data>,
        // For CoreTxBVTStateTransitionRule
        bvt_paths_to_inputs:      Vec<FieldBasedBinaryMHTPath<MHTP>>,
        bvt_paths_to_outputs:     Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_bvt_input_leaves:    Vec<Option<MHTP::Data>>,
        prev_bvt_output_leaves:   Vec<Option<MHTP::Data>>,
        prev_bvt_root:            Option<MHTP::Data>,
        new_bvt_root:             Option<MHTP::Data>,
    ) -> &mut Self
    {
        self
            .new_tx(tx_pay, fee)
            .new_tx_in_tree_rule(
                txs_tree_tx_path,
                prev_txs_tree_root, new_txs_tree_root
            )
            .new_tx_mst_state_transition_rule(
                mst_paths_to_inputs, mst_paths_to_outputs,
                prev_mst_root, new_mst_root
            )
            .new_tx_bvt_state_transition_rule(
                bvt_paths_to_inputs, bvt_paths_to_outputs, prev_bvt_input_leaves, prev_bvt_output_leaves,
                prev_bvt_root, new_bvt_root
            )
    }

    pub fn new_tx(
        &mut self,
        tx_pay: CoreTransaction<ConstraintF, G, H, TXP>,
        fee:    Option<ConstraintF>
    ) -> &mut Self
    {
        self.txs.push((tx_pay, fee));
        self.tx_in_tree_rules.push(None);
        self.mst_rules.push(None);
        self.bvt_rules.push(None);
        self
    }

    pub fn new_tx_in_tree_rule(
        &mut self,
        txs_tree_tx_path:   FieldBasedBinaryMHTPath<MHTP>,
        prev_txs_tree_root: Option<MHTP::Data>,
        new_txs_tree_root:  Option<MHTP::Data>,
    ) -> &mut Self
    {
        let rule = CoreTxInTreeRuleProverData::<ConstraintF, H, MHTP>::new(
            txs_tree_tx_path, prev_txs_tree_root, new_txs_tree_root
        );
        self.tx_in_tree_rules.push(Some(rule));
        self
    }

    pub fn new_tx_mst_state_transition_rule(
        &mut self,
        mst_paths_to_inputs:      Vec<FieldBasedBinaryMHTPath<MHTP>>,
        mst_paths_to_outputs:     Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_mst_root:            Option<MHTP::Data>,
        new_mst_root:             Option<MHTP::Data>,
    ) -> &mut Self
    {
        assert_eq!(mst_paths_to_inputs.len(), <TXP as TransactionParameters>::MAX_I_O_BOXES);
        assert_eq!(mst_paths_to_outputs.len(), <TXP as TransactionParameters>::MAX_I_O_BOXES);

        let rule = CoreTxMerkleTreeStateTransitionRuleProverData::<ConstraintF, H, MHTP>::new(
            mst_paths_to_inputs, mst_paths_to_outputs, prev_mst_root, new_mst_root
        );
        self.mst_rules.push(Some(rule));
        self
    }

    pub fn new_tx_bvt_state_transition_rule(
        &mut self,
        bvt_paths_to_inputs:      Vec<FieldBasedBinaryMHTPath<MHTP>>,
        bvt_paths_to_outputs:     Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_bvt_input_leaves:    Vec<Option<MHTP::Data>>,
        prev_bvt_output_leaves:   Vec<Option<MHTP::Data>>,
        prev_bvt_root:            Option<MHTP::Data>,
        new_bvt_root:             Option<MHTP::Data>,
    ) -> &mut Self
    {
        assert_eq!(bvt_paths_to_inputs.len(), <TXP as TransactionParameters>::MAX_I_O_BOXES);
        assert_eq!(bvt_paths_to_outputs.len(), <TXP as TransactionParameters>::MAX_I_O_BOXES);
        assert_eq!(prev_bvt_input_leaves.len(), <TXP as TransactionParameters>::MAX_I_O_BOXES);
        assert_eq!(prev_bvt_output_leaves.len(), <TXP as TransactionParameters>::MAX_I_O_BOXES);
        let rule = CoreTxBVTStateTransitionRuleProverData::<ConstraintF, H, MHTP>::new(
            bvt_paths_to_inputs, prev_bvt_input_leaves, bvt_paths_to_outputs, prev_bvt_output_leaves,
            prev_bvt_root, new_bvt_root
        );
        self.bvt_rules.push(Some(rule));
        self
    }
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> ConstraintSynthesizer<ConstraintF> for CoreTransactionCircuit<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: CoreTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        let bv_tree_batch_size = self.bv_tree_batch_size;
        self.txs
            .into_iter()
            .zip(self.tx_in_tree_rules.into_iter())
            .zip(self.mst_rules.into_iter())
            .zip(self.bvt_rules.into_iter())
            .enumerate()
            .map(|(i, ((((tx, fee), tx_in_tree_rule), mst_rule), bvt_rule))| {

                // Alloc tx_pay
                let mut tx_pay_g = CoreTransactionGadget::<ConstraintF, G, GG, H, HG, TXP>::alloc(
                    cs.ns(|| format!("alloc tx_pay_{}", i)),
                    || Ok(tx)
                )?;

                // Enforce public input fee is the same as tx one. Let's do it in this way
                // temporarily, it's easier and it's just one constraint
                let fee_g = FpGadget::<ConstraintF>::alloc_input(
                    cs.ns(|| "alloc input fee"),
                    || fee.as_ref().ok_or(SynthesisError::AssignmentMissing)
                )?;

                fee_g.enforce_equal(cs.ns(|| "public input fee == tx_pay.fee"), &tx_pay_g.fee)?;

                debug_assert!(tx_pay_g.inputs.len() == <TXP as TransactionParameters>::MAX_I_O_BOXES);
                debug_assert!(tx_pay_g.inputs.len() == tx_pay_g.outputs.len());

                // We need to enforce there is at least one input box
                tx_pay_g.inputs[0].is_padding.enforce_equal(
                    cs.ns(|| "at least one input box"),
                    &Boolean::constant(false)
                )?;

                // Enforce tx_hash_without_nonces
                tx_pay_g.enforce_tx_hash_without_nonces(
                    cs.ns(|| format!("enforce tx hash without nonces_{}", i))
                )?;

                // Enforce msg_to_sign, even if, currently,
                // tx_hash_without_nonces == message_to_sign
                tx_pay_g.enforce_message_to_sign(
                    cs.ns(|| format!("enforce message to sign_{}", i))
                )?;

                // Enforce TxSignatureRule (also enforces correct amount)
                CoreTxSignatureRule::<ConstraintF, G, GG, H, HG, TXP, MHTP>::new()
                    .enforce_rule(cs.ns(|| format!("Enforce signature_{}", i)), &tx_pay_g)?;

                // Enforce TxInTreeRule
                if tx_in_tree_rule.is_some() {
                    CoreTxInTreeRule::<ConstraintF, G, GG, H, HG, TXP, MHTP>::enforce(
                        cs.ns(|| format!("enforce tx_in_tree_rule_{}", i)),
                        tx_in_tree_rule.unwrap(),
                        &tx_pay_g
                    )?;
                }

                // Enforce MerkleStateTreeTransitionRule
                let mut mst_rule_g = None;
                if mst_rule.is_some() {
                    let rule = CoreTxMerkleTreeStateTransitionRule::<ConstraintF, G, GG, H, HG, TXP, MHTP>::conditionally_enforce(
                        cs.ns(|| format!("enforce mst_rule_{}", i)),
                        mst_rule.unwrap(),
                        &tx_pay_g,
                        &Boolean::constant(true)
                    )?;
                    mst_rule_g = Some(rule);
                }

                // Enforce BVT Transition Rule
                if bvt_rule.is_some() {
                    CoreTxBVTStateTransitionRule::<ConstraintF, G, GG, H, HG, TXP, MHTP>::conditionally_enforce(
                        cs.ns(|| format!("enforce bvt_rule_{}", i)),
                        mst_rule_g.unwrap(), // If bvt_rule is some, also mst_rule must've been some
                        bvt_rule.unwrap(),
                        &tx_pay_g,
                        &Boolean::constant(true),
                        bv_tree_batch_size
                    )?;
                }
                Ok(())
            }
        ).collect::<Result<(), SynthesisError>>()
    }
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> TransactionCircuit<ConstraintF, H, HG, MHTP>
for CoreTransactionCircuit<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: CoreTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    type InTreeRule = CoreTxInTreeRule<ConstraintF, G, GG, H, HG, TXP, MHTP>;
    type SignatureRule = CoreTxSignatureRule<ConstraintF, G, GG, H, HG, TXP, MHTP>;
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> CoinTransactionCircuit<ConstraintF, H, HG, MHTP>
for CoreTransactionCircuit<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: CoreTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    type StateUpdateRule = CoreTxMerkleTreeStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>;
    type BVTUpdateRule = CoreTxBVTStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>;
}