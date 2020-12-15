use algebra::fields::{
    PrimeField, FpParameters
};
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTreeParameters;
use r1cs_crypto::{
    crh::FieldBasedHashGadget,
    merkle_tree::{
        FieldBasedMerkleTreePathGadget,
        field_based_mht::FieldBasedBinaryMerkleTreePathGadget
    },
};
use r1cs_std::{
    bits::{
        boolean::Boolean, FromBitsGadget,
    },
    select::CondSelectGadget,
    fields::fp::FpGadget
};
use r1cs_core::{
    ConstraintSystem, SynthesisError
};
use std::marker::PhantomData;

/// Gadget needed to enforce a MerkleTree state transition. Namely:
/// given a SMT `tree`, a leaf `start` and another leaf `dest`,
/// enforces that `start` was removed from `tree` and `dest` was
/// added to `tree`. Where by "adding" and "removing" we mean
/// replacing the corresponding leaf with another one (in the same
/// position), whose value must be decided by the caller.
pub(crate) struct MerkleTreeTransitionGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    _tree_params: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _field:       PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> MerkleTreeTransitionGadget <P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    /// Given a `leaf` of a Merkle Tree, enforce and return, given its `path` to the root,
    /// a FpGadget representing the position of the leaf in the tree. In particular,
    /// the first log2(num_leaves) bits of the leaves, in decimal, stands for the index
    /// of the leaf, and the same holds for the bits of its Merkle Path to the root.
    pub(crate) fn conditionally_enforce_leaf_index<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        leaf: &HGadget::DataGadget,
        should_enforce: &Boolean
    ) -> Result<FpGadget<ConstraintF>, SynthesisError>
    {
        let leaf_index_bits = leaf.to_bits_with_length_restriction(
            cs.ns(|| "get leaf index bits"),
            (ConstraintF::Params::MODULUS_BITS as usize) - path.length()
        )?;

        path.conditionally_enforce_leaf_index_bits(
            cs.ns(|| "enforce leaf index bits"),
            leaf_index_bits.as_slice(),
            should_enforce
        )?;

        let leaf_index_g = FpGadget::<ConstraintF>::from_bits(
            cs.ns(|| "pack leaf index bits into a field element"),
            leaf_index_bits.as_slice()
        )?;

        Ok(leaf_index_g)
    }

    /// We need to enforce transition from `start_root` to `dest_root` following the
    /// replacement of `start_leaf` with `new_start_leaf` (at the same position) and `dest_leaf`
    /// with `new_dest_leaf` (at the same position). In order to do this, we introduce another
    /// Merkle Tree with root `interim_root` having, at the same position of `start_leaf` in
    /// `start_root` and `new_dest_leaf` in `dest_root`, `new_start_leaf` and `dest_leaf` instead.
    /// Then we prove:
    /// 1) `start_leaf` is part of the Merkle Tree with root `start_root` (using `start_path`);
    /// 2) `start_leaf` has been replaced with `new_start_leaf`, by applying to the latter the same
    ///    `start_path` used for 1) and enforcing the correct computation of `interim_root`;
    /// 3) `dest_leaf` is part of the Merkle Tree with root `interim_root` (using `dest_path`);
    /// 4) `dest_leaf` has been replaced with `new_dest_leaf`, by applying the same Merkle Path
    ///     used for 3) and enforcing the belonging of the latter to the Merkle Tree with root
    ///     `dest_root`.
    /// Note that:
    /// - 1) + 2) will prove that the value of `start_leaf` was part of Merkle Tree with root
    ///   `start_root` and it was changed in `new_start_leaf` in Merkle Tree with root
    ///   `interim_root`;
    /// - 3) + 4) will prove that the value of `dest_leaf` was part of Merkle Tree with root
    ///   `interim_root` and it was changed in `new_dest_leaf` in Merkle Tree with root
    ///   `dest_root`;
    /// - 1) + 2) + 3) will prove that the value of `dest_leaf` was unchanged and was indeed
    ///   `dest_leaf` in Merkle Trees with root `start_root` and `interim_root`;
    /// - 2) + 3) + 4) will prove that the value of `new_start_leaf` was unchanged and was
    ///   indeed `new_start_leaf` in Merkle Trees with root `interim_root` and `dest_root`;
    /// Thus all 4, combined, will prove our statement.
    /// If `should_enforce` is set to True, the function will do exactly what as stated above
    /// and return `dest_root`; otherwise does nothing and return the initial root `start_root`.
    pub(crate) fn conditionally_enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        start_root: &HGadget::DataGadget,
        start_path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        start_leaf: &HGadget::DataGadget,
        new_start_leaf: &HGadget::DataGadget,
        dest_path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        dest_leaf: &HGadget::DataGadget,
        new_dest_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        // Enforce replacement of `start_leaf` with `new_start_leaf` in tree `start_root`
        // producing a new tree with root `interim_root`
        let interim_root = Self::conditionally_enforce_leaf_replacement(
            cs.ns(|| "enforce replacement of start leaf"),
            start_root,
            start_path,
            start_leaf,
            new_start_leaf,
            should_enforce
        )?;

        // Enforce replacement of `dest_leaf` with `new_dest_leaf` in the tree with root
        // `interim_root`, producing a new tree with root `dest_root`
        let dest_root = Self::conditionally_enforce_leaf_replacement(
            cs.ns(|| "enforce replacement of dest leaf"),
            &interim_root,
            dest_path,
            dest_leaf,
            new_dest_leaf,
            should_enforce
        )?;

        Ok(dest_root)
    }

    /// If `should_enforce` is True, enforce replacement of `leaf` at `path`, with a `new_leaf`
    /// at the same `path`, in a Merkle Tree rooted at `root`, returning the new_root. Otherwise
    /// does nothing and returns the old root `root`.
    pub(crate) fn conditionally_enforce_leaf_replacement<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        root: &HGadget::DataGadget,
        path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        leaf: &HGadget::DataGadget,
        new_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        // Enforce `leaf` belonging to `root`.
        path.conditionally_check_membership(
            cs.ns(|| "leaf belongs to root"),
            root,
            leaf,
            should_enforce
        )?;

        // Enforce new Merkle Tree root after having replaced `leaf` with `new_leaf`.
        let new_root = path.enforce_merkle_path(
            cs.ns(|| "enforce new_root with new_start_leaf"),
            new_leaf
        )?;

        let return_root = HGadget::DataGadget::conditionally_select(
            cs.ns(|| "return new root or root"),
            should_enforce,
            &new_root,
            root
        )?;

        Ok(return_root)
    }
}
