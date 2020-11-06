pub mod gadgets;
pub mod base_tx_primitives;
pub mod constants;

use algebra::{PrimeField, ProjectiveCurve, ToConstraintField};
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use r1cs_std::{
    alloc::{
        AllocGadget, ConstantGadget
    },
    groups::GroupGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    fields::fp::FpGadget,
    eq::EqGadget,
    bits::boolean::Boolean
};
use r1cs_crypto::{
    merkle_tree::field_based_mht::FieldBasedMerkleTreePathGadget,
    FieldBasedHashGadget,
};
use crate::base_tx_circuit::{
    base_tx_primitives::transaction::{
        BaseTransaction, MAX_I_O_BOXES
    },
    gadgets::{
        sc_utxo_tree::SCUtxoTreeGadget,
        transaction::{
            BaseTransactionGadget, NoncedCoinBoxGadget,
        }
    },
    constants::BaseTransactionParameters,
};
use std::marker::PhantomData;

/// Base proof of transition for a single payment transaction, able to contain more than on
/// input/output coin box. The approach is to sequentially enforce one input/output transition
/// at time in the transaction.
pub struct BaseTransactionCircuit<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: BaseTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
>
{
    /////////////////////////// Witnesses

    /// A transaction with `MAX_I_O_BOXES` coin box inputs and `MAX_I_O_BOXES` coin box outputs
    tx_pay:                   Option<BaseTransaction<ConstraintF, G, H, TXP>>,

    /// Merkle Paths to the leaf where `tx_pay` will be placed in the Applied Payment Transactions Merkle Tree
    txs_tree_tx_path:         Option<FieldBasedBinaryMHTPath<MHTP>>,

    /// Merkle Paths to the leaves where the inputs are placed in the Merkle State Tree
    mst_paths_to_inputs:      Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Merkle Paths to the leaves where the outputs are placed in the Merkle State Tree
    mst_paths_to_outputs:     Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Merkle Paths to the leaves where the inputs are placed in the Bit Vector Tree
    bvt_paths_to_inputs:      Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Leaves corresponding to the Merkle paths in `bvt_paths_to_inputs`
    prev_bvt_input_leaves:    Vec<Option<MHTP::Data>>,

    /// Merkle Paths to the leaves where the outputs are placed in the Merkle State Tree
    bvt_paths_to_outputs:     Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Leaves corresponding to the Merkle paths in `bvt_paths_to_outputs`
    prev_bvt_output_leaves:   Vec<Option<MHTP::Data>>,

    /////////////////////////// Public inputs

    /// Merkle State Tree Root before applying `tx_pay`
    prev_mst_root:            Option<MHTP::Data>,

    /// Merkle State Tree Root after applying `tx_pay`
    new_mst_root:             Option<MHTP::Data>,

    /// Applied Payment Transactions Merkle Tree Root before applying `tx_pay`
    prev_txs_tree_root:       Option<MHTP::Data>,

    /// Applied Payment Transactions Merkle Tree Root after applying `tx_pay`
    new_txs_tree_root:        Option<MHTP::Data>,

    /// Fee associated to `tx_pay` explicitly needed as public input to bring it
    /// up recursively in the proof tree, since it will be used in the block proof
    /// to enforce the forger's payment
    fee:                      Option<FpGadget<ConstraintF>>,

    /// Bit Vector Tree Root before applying `tx_pay`
    prev_bvt_root:            Option<MHTP::Data>,

    /// Bit Vector Tree Root after applying `tx_pay`
    next_bvt_root:            Option<MHTP::Data>,

    /////////////////////////// Others

    _group_gadget:            PhantomData<GG>,
    _hash_gadget:             PhantomData<HG>,
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> ConstraintSynthesizer<ConstraintF> for BaseTransactionCircuit<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: BaseTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        // Preliminary checks
        assert_eq!(self.mst_paths_to_inputs.len(), MAX_I_O_BOXES);
        assert_eq!(self.mst_paths_to_inputs.len(), self.mst_paths_to_outputs.len());

        assert_eq!(self.bvt_paths_to_inputs.len(), MAX_I_O_BOXES);
        assert_eq!(self.bvt_paths_to_inputs.len(), self.bvt_paths_to_outputs.len());

        assert_eq!(self.prev_bvt_input_leaves.len(), MAX_I_O_BOXES);
        assert_eq!(self.prev_bvt_input_leaves.len(), self.prev_bvt_output_leaves.len());

        // 1. Check correctness of the MST transition. This will prove:
        // 		a) Existence of inputs in the scb_prev_mst_root
        // 		b) NULLs at the MST leaves where we insert outputs
        //		c) Removal of inputs and addition of outputs in the final scb_next_mst_root
        //      d) Outputs have been updated at the correct positions

        // Alloc tx_pay
        let tx_pay_g = BaseTransactionGadget::<ConstraintF, G, GG, H, HG, TXP>::alloc(
            cs.ns(|| "alloc tx_pay"),
            || self.tx_pay.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        debug_assert!(tx_pay_g.inputs.len() == MAX_I_O_BOXES);
        debug_assert!(tx_pay_g.inputs.len() == tx_pay_g.outputs.len());

        // Alloc MST roots
        let prev_mst_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc prev_mst_root"),
            || self.prev_mst_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let next_mst_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc next_mst_root"),
            || self.new_txs_tree_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        // Enforce MST transitions due to the application of tx_pay

        // We need to enforce there is at least one input box
        tx_pay_g.inputs[0].is_padding.enforce_equal(
            cs.ns(|| "at least one input box"),
            &Boolean::constant(false)
        )?;

        let tx_hash_without_nonces_g = tx_pay_g.enforce_tx_hash_without_nonces(
            cs.ns(|| "enforce tx hash without nonces")
        )?;

        let mut curr_mst_root_g = prev_mst_root_g.clone();

        for i in 0..MAX_I_O_BOXES {

            // Alloc merkle paths
            let mst_path_to_input_i_g = FieldBasedMerkleTreePathGadget::<MHTP, HG, ConstraintF>::alloc(
                cs.ns(|| format!("alloc mst_path_to_input_{}", i)),
                || self.mst_paths_to_inputs[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;

            let mst_path_to_output_i_g = FieldBasedMerkleTreePathGadget::<MHTP, HG, ConstraintF>::alloc(
                cs.ns(|| format!("alloc mst_path_to_output_{}", i)),
                || self.mst_paths_to_outputs[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;

            // Get output box leaf
            let output_box_index_i_g = FpGadget::<ConstraintF>::from_value(
                cs.ns(|| format!("hardcode box index_{}", i)),
                &ConstraintF::from(i as u8)
            );

            let output_leaf_i_g = NoncedCoinBoxGadget::<ConstraintF, G, GG, H, HG>::from_coin_box_gadget(
                cs.ns(|| format!("enforce nonced box for output_{}", i)),
                tx_pay_g.outputs[i].box_.clone(),
                tx_hash_without_nonces_g.clone(),
                output_box_index_i_g
            )?.id;

            // Enforce correct output position in MST
            mst_path_to_output_i_g.conditionally_enforce_leaf_index(
                cs.ns(|| "enforce correct output_box_index"),
                &output_leaf_i_g,
                &tx_pay_g.outputs[i].is_padding.not()
            )?;


            // Enforce state transitions
            // NOTE: I changed with respect to Dymitro's approach since that I update in the order
            // input1 -> output1 -> input2 -> output2 and not input1 -> input2 -> output1 -> output2.
            // However, it should be the same.

            let interim_mst_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_removal(
                cs.ns(|| format!("enforce mst update by removing input box {}", i)),
                &curr_mst_root_g,
                &mst_path_to_input_i_g,
                &tx_pay_g.inputs[i].box_.id,
                &tx_pay_g.inputs[i].is_padding.not()
            )?;

            curr_mst_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_insertion(
                cs.ns(|| format!("enforce mst update by adding output box {}", i)),
                &interim_mst_root_g,
                &mst_path_to_output_i_g,
                &output_leaf_i_g,
                &tx_pay_g.outputs[i].is_padding.not()
            )?;
        }

        // Check final mst root is equal to the expected one
        next_mst_root_g.enforce_equal(
            cs.ns(|| "final_mst_root == next_mst_root"),
            &curr_mst_root_g
        )?;

        // 2. Check tx_pay correctness:
        //      a) sum(input.amount) - sum(output.amount) - fee == 0
        //      b) for each input: vrfy(input.sig, tx.messageToSign) == True

        tx_pay_g.verify(
            cs.ns(|| "check tx_pay correctness"),
            // message_to_sign and tx_hash_without_nonces are the same for now
            tx_hash_without_nonces_g
        )?;

        // TBD...

        Ok(())
    }
}