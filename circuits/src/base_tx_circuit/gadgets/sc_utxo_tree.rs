use algebra::fields::PrimeField;
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTreeParameters;
use r1cs_crypto::{
    crh::FieldBasedHashGadget,
    merkle_tree::field_based_mht::FieldBasedMerkleTreePathGadget,
};
use r1cs_std::{
    alloc::ConstantGadget,
    bits::boolean::Boolean,
    fields::fp::FpGadget,
};
use r1cs_core::{
    ConstraintSystem, SynthesisError
};
use crate::base_tx_circuit::gadgets::transition::MerkleTreeTransitionGadget;
use std::marker::PhantomData;

pub struct SCUtxoTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    _tree_params: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _field:       PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> SCUtxoTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    /// If `should_enforce` is True, enforces removal of `start_leaf` located at `start_path`,
    /// and insertion of `new_dest_leaf` located at `dest_path`, in a Merkle Tree with root
    /// `start_root`, returning the root of the new Merkle Tree; otherwise does nothing and
    /// returns the old root `start_root`.
    pub fn conditionally_enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        start_root: &HGadget::DataGadget,
        start_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        start_leaf: &HGadget::DataGadget,
        dest_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        new_dest_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::conditionally_enforce_state_transition(
            cs, start_root, start_path, start_leaf, &null_leaf,
            dest_path, &null_leaf, new_dest_leaf, should_enforce,
        )
    }

    /// If `should_enforce` is True enforces removal of `leaf` located at `path` from a Merkle Tree
    /// rooted at `root`, and returns the root of the new tree, otherwise does nothing and returns
    /// the old root `root`.
    pub fn conditionally_enforce_leaf_removal<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        root: &HGadget::DataGadget,
        path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::conditionally_enforce_leaf_replacement(
            cs, root, path, leaf, &null_leaf, should_enforce,
        )
    }

    /// if `should_enforce` is True enforces the insertion in a Merkle Tree rooted at `root` of
    /// `new_leaf` located at `path`, and returns the root of the new tree, otherwise does nothing
    /// and returns the old root `root`.
    pub fn conditionally_enforce_leaf_insertion<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        root: &HGadget::DataGadget,
        path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        new_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::conditionally_enforce_leaf_replacement(
            cs, root, path, &null_leaf, new_leaf, should_enforce,
        )
    }
}


