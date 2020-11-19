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
        BaseTransaction, MAX_I_O_COIN_BOXES
    },
    gadgets::{
        sc_utxo_tree::SCUtxoTreeGadget,
        transaction::{
            BaseTransactionGadget, NoncedCoinBoxGadget,
        },
        transition::MerkleTreeTransitionGadget,
        bit_vector_tree::BitVectorTreeGadget,
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

    /// A transaction with `MAX_I_O_COIN_BOXES` coin box inputs and `MAX_I_O_COIN_BOXES` coin box outputs
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
    fee:                      Option<ConstraintF>,

    /// Bit Vector Tree Root before applying `tx_pay`
    prev_bvt_root:            Option<MHTP::Data>,

    /// Bit Vector Tree Root after applying `tx_pay`
    new_bvt_root:            Option<MHTP::Data>,

    /////////////////////////// Others

    /// Number of bits that are grouped to form a leaf of the Bit Vector Tree,
    /// expressed as a Field Element for simplicity.
    bv_tree_batch_size:       ConstraintF,

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
        assert_eq!(self.mst_paths_to_inputs.len(), MAX_I_O_COIN_BOXES);
        assert_eq!(self.mst_paths_to_inputs.len(), self.mst_paths_to_outputs.len());

        assert_eq!(self.bvt_paths_to_inputs.len(), MAX_I_O_COIN_BOXES);
        assert_eq!(self.bvt_paths_to_inputs.len(), self.bvt_paths_to_outputs.len());

        assert_eq!(self.prev_bvt_input_leaves.len(), MAX_I_O_COIN_BOXES);
        assert_eq!(self.prev_bvt_input_leaves.len(), self.prev_bvt_output_leaves.len());

        // Alloc tx_pay
        let tx_pay_g = BaseTransactionGadget::<ConstraintF, G, GG, H, HG, TXP>::alloc(
            cs.ns(|| "alloc tx_pay"),
            || self.tx_pay.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        debug_assert!(tx_pay_g.inputs.len() == MAX_I_O_COIN_BOXES);
        debug_assert!(tx_pay_g.inputs.len() == tx_pay_g.outputs.len());

        // We need to enforce there is at least one input box
        tx_pay_g.inputs[0].is_padding.enforce_equal(
            cs.ns(|| "at least one input box"),
            &Boolean::constant(false)
        )?;

        // Enforce tx_hash_without_nonces
        let tx_hash_without_nonces_g = tx_pay_g.enforce_tx_hash_without_nonces(
            cs.ns(|| "enforce tx hash without nonces")
        )?;

        // Currently tx_hash_without_nonces == message_to_sign
        let message_to_sign_g = tx_hash_without_nonces_g.clone();

        // 1. Check correctness of the MST transition. This will prove:
        // 		a) Existence of inputs in the scb_prev_mst_root
        // 		b) NULLs at the MST leaves where we insert outputs
        //		c) Removal of inputs and addition of outputs in the final scb_next_mst_root
        //      d) Outputs have been updated at the correct positions

        // 2. Check the correctness of the BVT transition. This will prove:
        //      a) Correct input and output indexes for BVT leaves
        //      b) Update of BVT leaves
        //      c) BVT tree state transition, enforced in the same way as 1

        // Alloc MST roots
        let prev_mst_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input prev_mst_root"),
            || self.prev_mst_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let new_mst_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input next_mst_root"),
            || self.new_mst_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        // Alloc BVT roots
        let prev_bvt_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input prev_bvt_root"),
            || self.prev_bvt_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let new_bvt_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input next_bvt_root"),
            || self.new_bvt_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let mut curr_mst_root_g = prev_mst_root_g;
        let mut curr_bvt_root_g = prev_bvt_root_g;

        for i in 0..MAX_I_O_COIN_BOXES {

            let is_input_i_padding = tx_pay_g.inputs[i].is_padding;
            let is_output_i_padding = tx_pay_g.outputs[i].is_padding;

            // Enforce MST transitions due to the application of tx_pay

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

            // Enforce correct input position in MST (we will need it later)
            let input_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index in mst for input_box_{}", i)),
                &mst_path_to_input_i_g,
                &tx_pay_g.inputs[i].box_.id,
                &is_input_i_padding.not()
            )?;

            // Enforce correct output position in MST
            let output_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index in mst for output_box_{}", i)),
                &mst_path_to_output_i_g,
                &output_leaf_i_g,
                &is_output_i_padding.not()
            )?;

            // Enforce MST transitions
            // NOTE: I changed with respect to Dmytro's approach since that I update in the order
            // input1 -> output1 -> input2 -> output2 and not input1 -> input2 -> output1 -> output2.
            // However, it should be the same.

            let interim_mst_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_removal(
                cs.ns(|| format!("enforce mst update by removing input box {}", i)),
                &curr_mst_root_g,
                &mst_path_to_input_i_g,
                &tx_pay_g.inputs[i].box_.id,
                &is_input_i_padding.not()
            )?;

            curr_mst_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_insertion(
                cs.ns(|| format!("enforce mst update by adding output box {}", i)),
                &interim_mst_root_g,
                &mst_path_to_output_i_g,
                &output_leaf_i_g,
                &is_output_i_padding.not()
            )?;

            // Enforce BVT transitions due to the application of tx_pay

            // Alloc merkle paths
            let bvt_path_to_input_i_g = FieldBasedMerkleTreePathGadget::<MHTP, HG, ConstraintF>::alloc(
                cs.ns(|| format!("alloc bvt_path_to_input_{}", i)),
                || self.bvt_paths_to_inputs[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;

            let bvt_path_to_output_i_g = FieldBasedMerkleTreePathGadget::<MHTP, HG, ConstraintF>::alloc(
                cs.ns(|| format!("alloc bvt_path_to_output_{}", i)),
                || self.bvt_paths_to_outputs[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;

            // Alloc prev leaves
            let prev_bvt_input_leaf_i_g = FpGadget::<ConstraintF>::alloc(
                cs.ns(|| format!("alloc prev_bvt_input_leaf_{}", i)),
                || self.prev_bvt_input_leaves[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;

            let prev_bvt_output_leaf_i_g = FpGadget::<ConstraintF>::alloc(
                cs.ns(|| format!("alloc prev_bvt_out9put_leaf_{}", i)),
                || self.prev_bvt_output_leaves[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;

            // Enforce BVT leaves index
            let bvt_input_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index for bvt_input_leaf_{}", i)),
                &bvt_path_to_input_i_g,
                &prev_bvt_input_leaf_i_g,
                &is_input_i_padding.not()
            )?;

            let bvt_output_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index for bvt_output_leaf_{}", i)),
                &bvt_path_to_output_i_g,
                &prev_bvt_output_leaf_i_g,
                &is_output_i_padding.not()
            )?;

            // Enforce BVT leaves update
            let next_bvt_input_leaf_i_g = BitVectorTreeGadget::<MHTP, HG, ConstraintF>::conditional_enforce_bv_leaf_update(
                cs.ns(|| format!("enforce bvt_input_leaf_{} update", i)),
                &prev_bvt_input_leaf_i_g,
                &bvt_input_leaf_i_index_g,
                &input_leaf_i_index_g,
                &self.bv_tree_batch_size,
                &is_input_i_padding.not()
            )?;

            let next_bvt_output_leaf_i_g = BitVectorTreeGadget::<MHTP, HG, ConstraintF>::conditional_enforce_bv_leaf_update(
                cs.ns(|| format!("enforce bvt_output_leaf_{} update", i)),
                &prev_bvt_output_leaf_i_g,
                &bvt_output_leaf_i_index_g,
                &output_leaf_i_index_g,
                &self.bv_tree_batch_size,
                &is_output_i_padding.not()
            )?;

            // Enforce BVT transitions
            // NOTE: I changed with respect to Dmytro's approach since that I update in the order
            // input1 -> output1 -> input2 -> output2 and not input1 -> input2 -> output1 -> output2.
            // However, it should be the same.

            let interim_bvt_root_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_replacement(
                cs.ns(|| format!("enforce bvt update for input_leaf_{}", i)),
                &curr_bvt_root_g,
                &bvt_path_to_input_i_g,
                &prev_bvt_input_leaf_i_g,
                &next_bvt_input_leaf_i_g,
                &is_input_i_padding.not()
            )?;

            curr_bvt_root_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_replacement(
                cs.ns(|| format!("enforce bvt update for output_leaf_{}", i)),
                &interim_bvt_root_g,
                &bvt_path_to_output_i_g,
                &prev_bvt_output_leaf_i_g,
                &next_bvt_output_leaf_i_g,
                &is_output_i_padding.not()
            )?;
        }

        // Check final mst root is equal to the expected one
        new_mst_root_g.enforce_equal(
            cs.ns(|| "final_mst_root == next_mst_root"),
            &curr_mst_root_g
        )?;

        // Check final bvt root is equal to the expected one
        new_bvt_root_g.enforce_equal(
            cs.ns(|| "final_bvt_root == next_bvt_root"),
            &curr_bvt_root_g
        )?;

        // 3. Check tx_pay correctness:
        //      a) sum(input.amount) - sum(output.amount) - fee == 0
        //      b) for each input: vrfy(input.sig, tx.messageToSign) == True

        // Enforce public input fee is the same as tx one. Let's do it in this way
        // temporarily, it's easier and it's just one constraint
        let fee_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input fee"),
            || self.fee.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        fee_g.enforce_equal(cs.ns(|| "public input fee == tx_pay.fee"), &tx_pay_g.fee)?;

        tx_pay_g.verify(
            cs.ns(|| "check tx_pay correctness"),
            // message_to_sign and tx_hash_without_nonces are the same for now
            message_to_sign_g.clone()
        )?;

        // 4. Check correct update of Applied Payment Transactions Merkle Tree
        //    a) Check that the leaf corresponding to `txs_tree_tx_path` is NULL in `prev_txs_tree_root`
        //    b) Check that the leaf corresponding to `txs_tree_tx_path` is H(tx_pay) in `new_txs_tree_root`

        // Alloc `txs_tree_tx_path`
        let txs_tree_tx_path_g = FieldBasedMerkleTreePathGadget::<MHTP, HG, ConstraintF>::alloc(
            cs.ns(|| "alloc txs_tree_tx_path"),
            || self.txs_tree_tx_path.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        // Alloc Applyied Payment Transaction Tree roots
        let prev_txs_tree_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input prev_txs_tree_root"),
            || self.prev_txs_tree_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let new_txs_tree_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input next_txs_tree_root"),
            || self.new_txs_tree_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        // Enforce tx_hash
        let tx_hash_g = tx_pay_g.enforce_tx_hash(
            cs.ns(|| "enforce tx_hash"),
            message_to_sign_g
        )?;

        // Enforce appending tx_hash to txs_tree
        let next_txs_tree_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_insertion(
            cs.ns(|| "enforce txs tree update by adding tx_pay"),
            &prev_txs_tree_root_g,
            &txs_tree_tx_path_g,
            &tx_hash_g,
            &Boolean::constant(true)
        )?;

        // Enforce next_txs_tree_root is correct
        new_txs_tree_root_g.enforce_equal(cs.ns(|| "enforce next_txs_tree_root"), &next_txs_tree_root_g)?;

        Ok(())
    }
}