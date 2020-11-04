use algebra::fields::PrimeField;
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTreeParameters;
use r1cs_crypto::{
    crh::FieldBasedHashGadget,
    merkle_tree::field_based_mht::FieldBasedMerkleTreePathGadget,
};
use r1cs_std::alloc::ConstantGadget;
use r1cs_core::{
    ConstraintSystem, SynthesisError
};
use crate::base_tx_circuit::gadgets::transition::MerkleTreeTransitionGadget;
use std::marker::PhantomData;

pub(crate) struct SCUtxoTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    _tree_params: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _field:       PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> SCUtxoTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    pub(crate) fn enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        start_root: &HGadget::DataGadget,
        start_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        start_leaf: &HGadget::DataGadget,
        dest_root: &HGadget::DataGadget,
        dest_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        new_dest_leaf: &HGadget::DataGadget,
    ) -> Result<(), SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::enforce_state_transition(
            cs, start_root, start_path, start_leaf, &null_leaf,
            dest_root, dest_path, &null_leaf, new_dest_leaf
        )?;

        Ok(())
    }
}


