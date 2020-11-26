use algebra::{PrimeField, ProjectiveCurve, ToConstraintField};
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use r1cs_std::{
    bits::boolean::Boolean,
    fields::fp::FpGadget,
    alloc::{
        AllocGadget, ConstantGadget
    },
    groups::GroupGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
    eq::EqGadget,
};
use r1cs_crypto::{
    FieldBasedHashGadget, merkle_tree::field_based_mht::FieldBasedBinaryMerkleTreePathGadget
};
use r1cs_core::{ConstraintSystem, SynthesisError};
use crate::{
    snark_builder::rules::tx_state_transition::TxTreeStateTransitionRule,
    base_tx_circuit::{
        base_tx_primitives::transaction::CoreTransaction,
        constants::CoreTransactionParameters,
        gadgets::{
            transaction::{CoreTransactionGadget, NoncedCoinBoxGadget},
            transition::MerkleTreeTransitionGadget,
            sc_utxo_tree::SCUtxoTreeGadget
        },
    }
};
use crate::base_tx_circuit::gadgets::bit_vector_tree::BitVectorTreeGadget;
use std::marker::PhantomData;
use crate::base_tx_circuit::constants::TransactionParameters;

pub struct CoreTxMerkleTreeStateTransitionRuleProverData<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>
>
{
    /// Merkle Paths to the leaves where the inputs are placed in the Merkle State Tree
    pub(crate) mst_paths_to_inputs:      Vec<FieldBasedBinaryMHTPath<MHTP>>,

    /// Merkle Paths to the leaves where the outputs are placed in the Merkle State Tree
    pub(crate) mst_paths_to_outputs:     Vec<FieldBasedBinaryMHTPath<MHTP>>,

    /// Merkle State Tree Root before applying `tx_pay`
    pub(crate) prev_mst_root:            Option<MHTP::Data>,

    /// Merkle State Tree Root after applying `tx_pay`
    pub(crate) new_mst_root:             Option<MHTP::Data>,
}

impl<ConstraintF, H, MHTP> CoreTxMerkleTreeStateTransitionRuleProverData<ConstraintF, H, MHTP>
    where
        ConstraintF: PrimeField,
        H: FieldBasedHash<Data = ConstraintF>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>
{
    pub fn new(
        paths_to_inputs:    Vec<FieldBasedBinaryMHTPath<MHTP>>,
        paths_to_outputs:   Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_root:          Option<H::Data>,
        next_root:          Option<H::Data>
    ) -> Self {

        Self {
            mst_paths_to_inputs: paths_to_inputs,
            mst_paths_to_outputs: paths_to_outputs,
            prev_mst_root: prev_root,
            new_mst_root: next_root
        }
    }
}

pub struct CoreTxMerkleTreeStateTransitionRule<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: CoreTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    input_leaves_index_g:         Vec<FpGadget<ConstraintF>>,
    output_leaves_index_g:        Vec<FpGadget<ConstraintF>>,
    output_leaves_g:              Vec<FpGadget<ConstraintF>>,

    _group:             PhantomData<G>,
    _group_gadget:      PhantomData<GG>,
    _hash:              PhantomData<H>,
    _hash_gadget:       PhantomData<HG>,
    _tx_params:         PhantomData<TXP>,
    _tree_params:       PhantomData<MHTP>
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> CoreTxMerkleTreeStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
where
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: CoreTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>
{
    pub fn new(
        input_leaves_index_g:         Vec<FpGadget<ConstraintF>>,
        output_leaves_index_g:        Vec<FpGadget<ConstraintF>>,
        output_leaves_g:              Vec<FpGadget<ConstraintF>>,
    ) -> Self {

        Self {
            input_leaves_index_g, output_leaves_index_g, output_leaves_g,
            _group: PhantomData,
            _group_gadget: PhantomData,
            _hash: PhantomData,
            _hash_gadget: PhantomData,
            _tx_params: PhantomData,
            _tree_params: PhantomData
        }
    }

    pub fn conditionally_enforce<CS: ConstraintSystem<ConstraintF>>(
        mut cs:                     CS,
        prover_data:                CoreTxMerkleTreeStateTransitionRuleProverData<ConstraintF, H, MHTP>,
        tx_gadget:                  &<Self as TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>>::TransactionGadget,
        should_enforce:             &Boolean,
    ) -> Result<Self, SynthesisError>
    {
        // Alloc MST roots
        let prev_mst_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input prev_mst_root"),
            || prover_data.prev_mst_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let next_mst_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input next_mst_root"),
            || prover_data.new_mst_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let mut mst_path_to_input_gs = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut mst_path_to_output_gs = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut output_leaves_g = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut input_leaves_index_g = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut output_leaves_index_g = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);

        for i in 0..<TXP as TransactionParameters>::MAX_I_O_BOXES {

            // Check if boxes are padding
            let should_enforce_input_i = Boolean::and(
                cs.ns(|| format!("should_enforce_input_box_{}", i)),
                &tx_gadget.inputs[i].is_padding.not(),
                should_enforce
            )?;

            let should_enforce_output_i = Boolean::and(
                cs.ns(|| format!("should_enforce_output_box_{}", i)),
                &tx_gadget.outputs[i].is_padding.not(),
                should_enforce
            )?;

            // Alloc merkle paths
            let mst_path_to_input_i_g = <Self as TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>>::MerklePathGadget::alloc(
                cs.ns(|| format!("alloc mst_path_to_input_{}", i)),
                || Ok(&prover_data.mst_paths_to_inputs[i])
            )?;

            let mst_path_to_output_i_g = <Self as TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>>::MerklePathGadget::alloc(
                cs.ns(|| format!("alloc mst_path_to_output_{}", i)),
                || Ok(&prover_data.mst_paths_to_outputs[i])
            )?;

            // Get output box leaf
            let output_box_index_i_g = FpGadget::<ConstraintF>::from_value(
                cs.ns(|| format!("hardcode box index_{}", i)),
                &ConstraintF::from(i as u8)
            );

            let output_leaf_i_g = NoncedCoinBoxGadget::<ConstraintF, G, GG, H, HG>::from_coin_box_gadget(
                cs.ns(|| format!("enforce nonced box for output_{}", i)),
                tx_gadget.outputs[i].box_.clone(),
                tx_gadget.tx_hash_without_nonces_g.clone().unwrap(),
                output_box_index_i_g
            )?.id;

            // Enforce correct input position in MST
            let input_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index in mst for input_box_{}", i)),
                &mst_path_to_input_i_g,
                &tx_gadget.inputs[i].box_.id,
                &should_enforce_input_i
            )?;
            input_leaves_index_g.push(input_leaf_i_index_g);
            mst_path_to_input_gs.push(mst_path_to_input_i_g);

            // Enforce correct output position in MST
            let output_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index in mst for output_box_{}", i)),
                &mst_path_to_output_i_g,
                &output_leaf_i_g,
                &should_enforce_output_i
            )?;
            output_leaves_index_g.push(output_leaf_i_index_g);
            output_leaves_g.push(output_leaf_i_g);
            mst_path_to_output_gs.push(mst_path_to_output_i_g);
        }

        let new_instance = Self {
            input_leaves_index_g,
            output_leaves_index_g,
            output_leaves_g,
            _group: PhantomData,
            _group_gadget: PhantomData,
            _hash: PhantomData,
            _hash_gadget: PhantomData,
            _tx_params: PhantomData,
            _tree_params: PhantomData
        };

        new_instance.conditionally_enforce_rule(
            cs.ns(|| "enforce state transition"),
            tx_gadget,
            mst_path_to_input_gs,
            mst_path_to_output_gs,
            prev_mst_root_g,
            next_mst_root_g,
            should_enforce
        )?;

        Ok(new_instance)
    }
}


impl<ConstraintF, G, GG, H, HG, MHTP, TXP> TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP> for
    CoreTxMerkleTreeStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
where
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: CoreTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    type MerklePathGadget = FieldBasedBinaryMerkleTreePathGadget<MHTP, HG, ConstraintF>;
    type Transaction = CoreTransaction<ConstraintF, G, H, TXP>;
    type TransactionGadget = CoreTransactionGadget<ConstraintF, G, GG, H, HG, TXP>;

    fn conditionally_enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs:                  CS,
        tx_gadget:               &Self::TransactionGadget,
        path_to_input_gs:        Vec<Self::MerklePathGadget>,
        path_to_output_gs:       Vec<Self::MerklePathGadget>,
        prev_root:               FpGadget<ConstraintF>,
        next_root:               FpGadget<ConstraintF>,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> {

        let mut curr_mst_root_g = prev_root;
        for i in 0..<TXP as TransactionParameters>::MAX_I_O_BOXES {

            // Check if boxes are padding
            let should_enforce_input_i = Boolean::and(
                cs.ns(|| format!("should_enforce_input_box_{}", i)),
                &tx_gadget.inputs[i].is_padding.not(),
                should_enforce
            )?;

            let should_enforce_output_i = Boolean::and(
                cs.ns(|| format!("should_enforce_output_box_{}", i)),
                &tx_gadget.outputs[i].is_padding.not(),
                should_enforce
            )?;

            // Enforce MST transitions
            // NOTE: I changed with respect to Dmytro's approach since that I update in the order
            // input1 -> output1 -> input2 -> output2 and not input1 -> input2 -> output1 -> output2.
            // However, it should be the same.

            let interim_mst_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_removal(
                cs.ns(|| format!("enforce mst update by removing input box {}", i)),
                &curr_mst_root_g,
                &path_to_input_gs[i],
                &tx_gadget.inputs[i].box_.id,
                &should_enforce_input_i
            )?;

            curr_mst_root_g = SCUtxoTreeGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_insertion(
                cs.ns(|| format!("enforce mst update by adding output box {}", i)),
                &interim_mst_root_g,
                &path_to_output_gs[i],
                &self.output_leaves_g[i],
                &should_enforce_output_i
            )?;
        }

        // Check final mst root is equal to the expected one
        next_root.conditional_enforce_equal(
            cs.ns(|| "final_mst_root == next_mst_root"),
            &curr_mst_root_g,
            should_enforce
        )?;

        Ok(())
    }
}

/////////////////////////////

pub struct CoreTxBVTStateTransitionRuleProverData<
    ConstraintF: PrimeField,
    H: FieldBasedHash<Data = ConstraintF>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>
> {
    /// Merkle Paths to the leaves where the inputs are placed in the Bit Vector Tree
    bvt_paths_to_inputs:              Vec<FieldBasedBinaryMHTPath<MHTP>>,

    /// Leaves corresponding to the Merkle paths in `bvt_paths_to_inputs`
    prev_bvt_input_leaves:            Vec<Option<MHTP::Data>>,

    /// Merkle Paths to the leaves where the outputs are placed in the Merkle State Tree
    bvt_paths_to_outputs:             Vec<FieldBasedBinaryMHTPath<MHTP>>,

    /// Leaves corresponding to the Merkle paths in `bvt_paths_to_outputs`
    prev_bvt_output_leaves:           Vec<Option<MHTP::Data>>,

    /// Bit Vector Tree Root before applying tx
    prev_bvt_root:                    Option<MHTP::Data>,

    /// Bit Vector Tree Root after applying tx
    new_bvt_root:                     Option<MHTP::Data>,
}

impl<ConstraintF, H, MHTP> CoreTxBVTStateTransitionRuleProverData<ConstraintF, H, MHTP>
    where
        ConstraintF: PrimeField,
        H: FieldBasedHash<Data = ConstraintF>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>
{
    pub fn new(
        bvt_paths_to_inputs:              Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_bvt_input_leaves:            Vec<Option<MHTP::Data>>, //This can be a vector of LeafUpdateRuleProverData ?
        bvt_paths_to_outputs:             Vec<FieldBasedBinaryMHTPath<MHTP>>,
        prev_bvt_output_leaves:           Vec<Option<MHTP::Data>>, //This can be a vector of LeafUpdateRuleProverData ?
        prev_bvt_root:                    Option<MHTP::Data>,
        new_bvt_root:                     Option<MHTP::Data>,
    ) -> Self
    {
        Self{
            bvt_paths_to_inputs, prev_bvt_input_leaves,
            bvt_paths_to_outputs, prev_bvt_output_leaves,
            prev_bvt_root, new_bvt_root
        }
    }
}

pub struct CoreTxBVTStateTransitionRule<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: CoreTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    mst_rule:                   CoreTxMerkleTreeStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>,
    prev_bvt_input_leaves_g:    Vec<FpGadget<ConstraintF>>, //This can be a vector of LeafUpdateRule ?
    prev_bvt_output_leaves_g:   Vec<FpGadget<ConstraintF>>, //This can be a vector of LeafUpdateRule ?
    bv_tree_batch_size:         usize,
}

impl<ConstraintF, G, GG, H, HG, TXP, MHTP> CoreTxBVTStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: CoreTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    pub fn new(
        mst_rule:                   CoreTxMerkleTreeStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>,
        prev_bvt_input_leaves_g:    Vec<FpGadget<ConstraintF>>,
        prev_bvt_output_leaves_g:   Vec<FpGadget<ConstraintF>>,
        bv_tree_batch_size:         usize,
    ) -> Self
    {
        Self {
            mst_rule, prev_bvt_input_leaves_g, prev_bvt_output_leaves_g, bv_tree_batch_size
        }
    }

    pub fn conditionally_enforce<CS: ConstraintSystem<ConstraintF>>(
        mut cs:             CS,
        mst_rule:           CoreTxMerkleTreeStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>,
        prover_data:        CoreTxBVTStateTransitionRuleProverData<ConstraintF, H, MHTP>,
        tx_gadget:          &<Self as TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>>::TransactionGadget,
        should_enforce:     &Boolean,
        bv_tree_batch_size: usize,
    ) -> Result<Self, SynthesisError>
    {
        // Alloc BVT roots
        let prev_bvt_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input prev_bvt_root"),
            || prover_data.prev_bvt_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let new_bvt_root_g = FpGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc input next_bvt_root"),
            || prover_data.new_bvt_root.as_ref().ok_or(SynthesisError::AssignmentMissing)
        )?;

        let mut bvt_path_to_input_gs = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut bvt_path_to_output_gs = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut prev_bvt_input_leaves_g = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);
        let mut prev_bvt_output_leaves_g = Vec::with_capacity(<TXP as TransactionParameters>::MAX_I_O_BOXES);

        for i in 0..<TXP as TransactionParameters>::MAX_I_O_BOXES {

            // Alloc merkle paths
            let bvt_path_to_input_i_g = <Self as TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>>::MerklePathGadget::alloc(
                cs.ns(|| format!("alloc bvt_path_to_input_{}", i)),
                || Ok(&prover_data.bvt_paths_to_inputs[i])
            )?;
            bvt_path_to_input_gs.push(bvt_path_to_input_i_g);

            let bvt_path_to_output_i_g = <Self as TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP>>::MerklePathGadget::alloc(
                cs.ns(|| format!("alloc bvt_path_to_output_{}", i)),
                || Ok(&prover_data.bvt_paths_to_outputs[i])
            )?;
            bvt_path_to_output_gs.push(bvt_path_to_output_i_g);

            // Alloc prev leaves
            let prev_bvt_input_leaf_i_g = FpGadget::<ConstraintF>::alloc(
                cs.ns(|| format!("alloc prev_bvt_input_leaf_{}", i)),
                || prover_data.prev_bvt_input_leaves[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;
            prev_bvt_input_leaves_g.push(prev_bvt_input_leaf_i_g);

            let prev_bvt_output_leaf_i_g = FpGadget::<ConstraintF>::alloc(
                cs.ns(|| format!("alloc prev_bvt_out9put_leaf_{}", i)),
                || prover_data.prev_bvt_output_leaves[i].as_ref().ok_or(SynthesisError::AssignmentMissing)
            )?;
            prev_bvt_output_leaves_g.push(prev_bvt_output_leaf_i_g);
        }

        let new_instance = Self {
            mst_rule,
            prev_bvt_input_leaves_g,
            prev_bvt_output_leaves_g,
            bv_tree_batch_size,
        };

        new_instance.conditionally_enforce_rule(
            cs.ns(|| "enforce bvt state transition"),
            tx_gadget,
            bvt_path_to_input_gs,
            bvt_path_to_output_gs,
            prev_bvt_root_g,
            new_bvt_root_g,
            should_enforce
        )?;

        Ok(new_instance)
    }
}


impl<ConstraintF, G, GG, H, HG, MHTP, TXP> TxTreeStateTransitionRule<ConstraintF, H, HG, MHTP> for
CoreTxBVTStateTransitionRule<ConstraintF, G, GG, H, HG, TXP, MHTP>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TXP: CoreTransactionParameters<ConstraintF, G>,
        MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
{
    type MerklePathGadget = FieldBasedBinaryMerkleTreePathGadget<MHTP, HG, ConstraintF>;
    type Transaction = CoreTransaction<ConstraintF, G, H, TXP>;
    type TransactionGadget = CoreTransactionGadget<ConstraintF, G, GG, H, HG, TXP>;

    fn conditionally_enforce_rule<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        tx_gadget:          &Self::TransactionGadget,
        path_to_input_gs:   Vec<Self::MerklePathGadget>,
        path_to_output_gs:  Vec<Self::MerklePathGadget>,
        prev_root:          FpGadget<ConstraintF>,
        next_root:          FpGadget<ConstraintF>,
        should_enforce:     &Boolean
    ) -> Result<(), SynthesisError> {

        let mut curr_bvt_root_g = prev_root;

        for i in 0..<TXP as TransactionParameters>::MAX_I_O_BOXES {

            // Check if boxes are padding
            let should_enforce_input_i = Boolean::and(
                cs.ns(|| format!("should_enforce_input_box_{}", i)),
                &tx_gadget.inputs[i].is_padding.not(),
                should_enforce
            )?;

            let should_enforce_output_i = Boolean::and(
                cs.ns(|| format!("should_enforce_output_box_{}", i)),
                &tx_gadget.outputs[i].is_padding.not(),
                should_enforce
            )?;

            // Enforce BVT leaves index
            let bvt_input_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index for bvt_input_leaf_{}", i)),
                &path_to_input_gs[i],
                &self.prev_bvt_input_leaves_g[i],
                &should_enforce_input_i
            )?;

            let bvt_output_leaf_i_index_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_index(
                cs.ns(|| format!("enforce correct index for bvt_output_leaf_{}", i)),
                &path_to_output_gs[i],
                &self.prev_bvt_output_leaves_g[i],
                &should_enforce_output_i
            )?;

            // Enforce BVT leaves update
            let next_bvt_input_leaf_i_g = BitVectorTreeGadget::<MHTP, HG, ConstraintF>::conditional_enforce_bv_leaf_update(
                cs.ns(|| format!("enforce bvt_input_leaf_{} update", i)),
                &self.prev_bvt_input_leaves_g[i],
                &bvt_input_leaf_i_index_g,
                &self.mst_rule.input_leaves_index_g[i],
                self.bv_tree_batch_size,
                &should_enforce_input_i
            )?;

            let next_bvt_output_leaf_i_g = BitVectorTreeGadget::<MHTP, HG, ConstraintF>::conditional_enforce_bv_leaf_update(
                cs.ns(|| format!("enforce bvt_output_leaf_{} update", i)),
                &self.prev_bvt_output_leaves_g[i],
                &bvt_output_leaf_i_index_g,
                &self.mst_rule.output_leaves_index_g[i],
                self.bv_tree_batch_size,
                &should_enforce_output_i
            )?;

            // Enforce BVT transitions
            // NOTE: I changed with respect to Dmytro's approach since that I update in the order
            // input1 -> output1 -> input2 -> output2 and not input1 -> input2 -> output1 -> output2.
            // However, it should be the same.

            let interim_bvt_root_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_replacement(
                cs.ns(|| format!("enforce bvt update for input_leaf_{}", i)),
                &curr_bvt_root_g,
                &path_to_input_gs[i],
                &self.prev_bvt_input_leaves_g[i],
                &next_bvt_input_leaf_i_g,
                &should_enforce_input_i,
            )?;

            curr_bvt_root_g = MerkleTreeTransitionGadget::<MHTP, HG, ConstraintF>::conditionally_enforce_leaf_replacement(
                cs.ns(|| format!("enforce bvt update for output_leaf_{}", i)),
                &interim_bvt_root_g,
                &path_to_output_gs[i],
                &self.prev_bvt_output_leaves_g[i],
                &next_bvt_output_leaf_i_g,
                &should_enforce_output_i
            )?;
        }

        // Check final bvt root is equal to the expected one
        next_root.conditional_enforce_equal(
            cs.ns(|| "final_bvt_root == next_bvt_root"),
            &curr_bvt_root_g,
            should_enforce
        )?;

        Ok(())
    }
}