use algebra::fields::PrimeField;
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTreeParameters;
use r1cs_crypto::{
    crh::FieldBasedHashGadget,
    merkle_tree::field_based_mht::FieldBasedMerkleTreePathGadget,
};
use r1cs_std::{
    eq::EqGadget,
    bits::boolean::Boolean
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
        HGadget: FieldBasedHashGadget<P::H, ConstraintF>,
        ConstraintF: PrimeField,
{
    _tree_params: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _field:       PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> MerkleTreeTransitionGadget <P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF>,
        ConstraintF: PrimeField,
{

    pub(crate) fn enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        cs: CS,
        start_root: &HGadget::DataGadget,
        start_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        start_leaf: &HGadget::DataGadget,
        new_start_leaf: &HGadget::DataGadget,
        dest_root: &HGadget::DataGadget,
        dest_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        dest_leaf: &HGadget::DataGadget,
        new_dest_leaf: &HGadget::DataGadget,
    ) -> Result<(), SynthesisError>
    {
        Self::conditionally_enforce_state_transition(
            cs, start_root, start_path,
            start_leaf, new_start_leaf, dest_root,
            dest_path, dest_leaf, new_dest_leaf,
            &Boolean::Constant(true)
        )
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
    pub(crate) fn conditionally_enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        start_root: &HGadget::DataGadget,
        start_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        start_leaf: &HGadget::DataGadget,
        new_start_leaf: &HGadget::DataGadget,
        dest_root: &HGadget::DataGadget,
        dest_path: &FieldBasedMerkleTreePathGadget<P, HGadget, ConstraintF>,
        dest_leaf: &HGadget::DataGadget,
        new_dest_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>
    {
        // Enforce `start_leaf` belonging to `start_root`.
        start_path.conditionally_check_membership(
            cs.ns(|| "start_leaf belongs to start_root"),
            start_root,
            start_leaf,
            should_enforce
        )?;

        // Enforce new Merkle Tree root after having replaced `start_leaf` with `new_start_leaf`.
        let interim_root_1 = start_path.enforce_merkle_path(
            cs.ns(|| "enforce interim root with new_start_leaf"),
            new_start_leaf
        )?;

        // Enforce `dest_leaf` belonging to the same Merkle Tree of `new_start_before`
        let interim_root_2 = dest_path.enforce_merkle_path(
            cs.ns(|| "enforce interim root with dest_leaf"),
            dest_leaf
        )?;

        // We can save this instruction by calling `conditionally_check_membership`
        // with `interim_root_1` in the instruction above, but let's keep this for
        // better readability (number of constraints is the same anyway).
        interim_root_1.conditional_enforce_equal(
            cs.ns(|| "interim_root_1 == interim_root_2"),
            &interim_root_2,
            should_enforce,
        )?;

        // Finally, enforce `new_dest_leaf` belonging to `dest_root`
        dest_path.conditionally_check_membership(
            cs.ns(|| "new_dest_leaf belongs to dest_root"),
            dest_root,
            new_dest_leaf,
            should_enforce
        )?;

        Ok(())
    }
}
