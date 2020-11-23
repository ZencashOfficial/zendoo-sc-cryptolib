use algebra::fields::{
    PrimeField, FpParameters,
};
use std::marker::PhantomData;
use r1cs_std::{
    fields::{
        fp::FpGadget, FieldGadget,
    },
    bits::boolean::Boolean,
    select::CondSelectGadget,
};
use r1cs_core::{
    ConstraintSystem, SynthesisError
};
use primitives::FieldBasedMerkleTreeParameters;
use r1cs_crypto::FieldBasedHashGadget;

pub struct BitVectorTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    _tree_params: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _field:       PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> BitVectorTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    /// PRE-REQUISITES:
    /// - `bv_leaf_index` is already enforced to the be the index of `bv_leaf`;
    /// - `utxo_leaf_index` is alreay enforced to be the index of the corresponding
    ///   leaf in the SCUtxoMerkleTree;
    /// - `bv_tree_batch_size` <= ConstraintF::CAPACITY
    /// The function enforces correct update of the correct bit of `bv_leaf`, desumed
    /// (and enforced) from `utxo_leaf_index`, `bv_tree_batch_size` and `bv_leaf_index` itself.
    pub(crate) fn conditional_enforce_bv_leaf_update<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        bv_leaf: &FpGadget<ConstraintF>,
        bv_leaf_index: &FpGadget<ConstraintF>,
        utxo_leaf_index: &FpGadget<ConstraintF>,
        bv_tree_batch_size: &ConstraintF,
        should_enforce: &Boolean,
    ) -> Result<FpGadget<ConstraintF>, SynthesisError>
    {
        // bv_leaf_index = utxo_leaf_index / bv_tree_batch_size
        // bit_idx_inside_bv_leaf = utxo_leaf_index % bv_tree_batch_size
        //                        = utxo_leaf_index - bv_leaf_index * bv_tree_batch_size
        let bit_idx_inside_bv_leaf = bv_leaf_index
            .mul_by_constant(cs.ns(|| "bv_leaf_index * bv_tree_batch_size"), bv_tree_batch_size)?
            .negate(cs.ns(|| "- bv_leaf_index * bv_tree_batch_size"))?
            .add(cs.ns(|| " utxo_leaf_index - bv_leaf_index * bv_tree_batch_size"), utxo_leaf_index)?;

        let new_bv_leaf = {

            // bit_idx_inside_bv_leaf will not be bigger than log2(CAPACITY) = log2(MODULUS_BITS - 1)
            // so we can save some constraints by skipping unset bits
            let to_skip = (ConstraintF::Params::MODULUS_BITS as usize) -
                ((ConstraintF::Params::CAPACITY as f64).log2() as usize);

            let bit_idx_inside_bv_leaf_bits = bit_idx_inside_bv_leaf
                .to_bits_with_length_restriction(
                    cs.ns(|| "bit_idx_inside_bv_leaf_to_bits"),
                    to_skip
                )?;

            // new_bv_leaf = bv_leaf + 2^bit_idx_inside_bv_leaf
            let two = FpGadget::<ConstraintF>::one(cs.ns(|| "alloc one"))?
                .double(cs.ns(|| "two"))?;
            let two_pow_bit_idx_inside_bv_leaf = two.pow(
                cs.ns(|| "2^bit_idx_inside_bv_leaf_bits"),
                bit_idx_inside_bv_leaf_bits.as_slice()
            )?;

            bv_leaf.add(cs.ns(|| "bv_leaf + 2^bit_idx_inside_bv_leaf"), &two_pow_bit_idx_inside_bv_leaf)
        }?;

        FpGadget::<ConstraintF>::conditionally_select(
            cs.ns(|| "select bv_leaf or new_bv_leaf"),
            should_enforce,
            &new_bv_leaf,
            &bv_leaf
        )
    }
}

