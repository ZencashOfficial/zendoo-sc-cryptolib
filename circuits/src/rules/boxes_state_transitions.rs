use algebra::PrimeField;
use crate::{Transaction, TransactionProverData};
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedHash, FieldBasedSignatureScheme};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget};
use crate::transaction::constraints::TransactionGadget;
use std::marker::PhantomData;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::bits::boolean::Boolean;
use crate::base_gadgets::transition::MerkleTreeTransitionGadget;
use r1cs_std::fields::fp::FpGadget;
use r1cs_std::alloc::ConstantGadget;
use r1cs_std::eq::EqGadget;
use crate::transaction_box::constraints::TransactionBoxGadget;
use crate::base_gadgets::bit_vector_tree::BitVectorTreeGadget;

pub struct BoxesStateTransitionGadget<
    ConstraintF: PrimeField,
    T:           Transaction,
    D:           TransactionProverData<T>,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TG:          TransactionGadget<ConstraintF, T, D, P, H, HG, S, SG>
>
{
    _field:             PhantomData<ConstraintF>,
    _tx:                PhantomData<T>,
    _data:              PhantomData<D>,
    _tree:              PhantomData<P>,
    _hash:              PhantomData<H>,
    _hash_gadget:       PhantomData<HG>,
    _sig:               PhantomData<S>,
    _sig_gadget:        PhantomData<SG>,
    _tx_gadget:         PhantomData<TG>,
}

impl<ConstraintF, T, D, P, H, HG, S, SG, TG> BoxesStateTransitionGadget<ConstraintF, T, D, P, H, HG, S, SG, TG>
    where
        ConstraintF: PrimeField,
        T:           Transaction,
        D:           TransactionProverData<T>,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        TG:          TransactionGadget<ConstraintF, T, D, P, H, HG, S, SG>
{
    pub fn enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        tx_g: &TG,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> {

        let input_boxes_g = tx_g.get_coin_inputs();
        let output_boxes_g = tx_g.get_coin_outputs();

        let null_leaf_g = FpGadget::<ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        let mut curr_mst_root_g = tx_g.get_prev_mst_root().clone();
        let mut curr_bvt_root_g = tx_g.get_prev_bvt_root().clone();

        for (i, (input_box_data, output_box_data))
            in input_boxes_g.iter().zip(output_boxes_g.iter()).enumerate() {

            let should_replace_input = Boolean::and(
                cs.ns(|| format!("should_replace_input_{}", i)),
                should_enforce,
                &input_box_data.is_phantom().not()
            )?;

            let should_replace_output = Boolean::and(
                cs.ns(|| format!("should_replace_output_{}", i)),
                should_enforce,
                &output_box_data.is_phantom().not()
            )?;

            // Enforce MST transitions
            let interim_mst_root_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_replacement
                (
                    cs.ns(|| format!("enforce mst update by removing input box {}", i)),
                    &curr_mst_root_g,
                    input_box_data.get_path_in_mst(),
                    &input_box_data.id,
                    &null_leaf_g,
                    &should_replace_input,
                )?;

            curr_mst_root_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_replacement
                (
                    cs.ns(|| format!("enforce mst update by adding output box {}", i)),
                    &interim_mst_root_g,
                    output_box_data.get_path_in_mst(),
                    &null_leaf_g,
                    &output_box_data.id,
                    &should_replace_output,
                )?;

            // Enforce correct input position in MST (we will need it later)
            let input_leaf_i_index_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_index
                (
                    cs.ns(|| format!("enforce correct index in mst for input_box_{}", i)),
                    input_box_data.get_path_in_mst(),
                    &input_box_data.id,
                    &should_replace_input,
                )?;

            // Enforce correct output position in MST
            let output_leaf_i_index_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_index
                (
                    cs.ns(|| format!("enforce correct index in mst for output_box_{}", i)),
                    output_box_data.get_path_in_mst(),
                    &output_box_data.id,
                    &should_replace_output,
                )?;

            // Enforce BVT leaves index
            let bvt_input_leaf_i_index_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_index
                (
                    cs.ns(|| format!("enforce correct index for bvt_input_leaf_{}", i)),
                    input_box_data.get_path_in_bvt(),
                    input_box_data.get_leaf_val_in_bvt(),
                    &should_replace_input
                )?;

            let bvt_output_leaf_i_index_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_index
                (
                    cs.ns(|| format!("enforce correct index for bvt_output_leaf_{}", i)),
                    output_box_data.get_path_in_bvt(),
                    output_box_data.get_leaf_val_in_bvt(),
                    &should_replace_output
                )?;

            // Enforce BVT leaves update
            let next_bvt_input_leaf_i_g = BitVectorTreeGadget::<P, HG, ConstraintF>::conditional_enforce_bv_leaf_update
                (
                    cs.ns(|| format!("enforce bvt_input_leaf_{} update", i)),
                    input_box_data.get_leaf_val_in_bvt(),
                    &bvt_input_leaf_i_index_g,
                    &input_leaf_i_index_g,
                    tx_g.get_bvt_batch_size(),
                    &should_replace_input
                )?;

            let next_bvt_output_leaf_i_g = BitVectorTreeGadget::<P, HG, ConstraintF>::conditional_enforce_bv_leaf_update
                (
                    cs.ns(|| format!("enforce bvt_output_leaf_{} update", i)),
                    output_box_data.get_leaf_val_in_bvt(),
                    &bvt_output_leaf_i_index_g,
                    &output_leaf_i_index_g,
                    tx_g.get_bvt_batch_size(),
                    &should_replace_output
                )?;

            // Enforce BVT transitions
            let interim_bvt_root_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_replacement
                (
                    cs.ns(|| format!("enforce bvt update for input_leaf_{}", i)),
                    &curr_bvt_root_g,
                    input_box_data.get_path_in_bvt(),
                    input_box_data.get_leaf_val_in_bvt(),
                    &next_bvt_input_leaf_i_g,
                    &should_replace_input
                )?;

            curr_bvt_root_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_replacement
                (
                    cs.ns(|| format!("enforce bvt update for output_leaf_{}", i)),
                    &interim_bvt_root_g,
                    output_box_data.get_path_in_bvt(),
                    output_box_data.get_leaf_val_in_bvt(),
                    &next_bvt_output_leaf_i_g,
                    &should_replace_output
                )?;
        }

        // Check final mst root is equal to the expected one
        tx_g.get_next_mst_root().conditional_enforce_equal(
            cs.ns(|| "final_mst_root == next_mst_root"),
            &curr_mst_root_g,
            should_enforce,
        )?;

        // Check final bvt root is equal to the expected one
        tx_g.get_next_bvt_root().conditional_enforce_equal(
            cs.ns(|| "final_bvt_root == next_bvt_root"),
            &curr_bvt_root_g,
            should_enforce,
        )?;

        Ok(())
    }
}