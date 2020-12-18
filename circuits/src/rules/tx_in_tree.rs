use algebra::Field;
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

pub struct TransactionInTreeGadget<
    ConstraintF: Field,
    T:           Transaction,
    D:           TransactionProverData<T>,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    TG:          TransactionGadget<T, D, P, H, HG, S, SG>
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

impl<ConstraintF, T, D, P, H, HG, S, SG, TG> TransactionInTreeGadget<ConstraintF, T, D, P, H, HG, S, SG, TG>
    where
        ConstraintF: Field,
        T:           Transaction,
        D:           TransactionProverData<T>,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        TG:          TransactionGadget<T, D, P, H, HG, S, SG>
{
    pub fn enforce_tx_in_tree<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        tx_g: &TG,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> {

        let null_leaf_g = FpGadget::<ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap()[0]
        );

        let new_tree_root_g = MerkleTreeTransitionGadget::<P, HG, ConstraintF>::conditionally_enforce_leaf_replacement(
            cs.ns(|| "enforce tx_hash insertion in block_txs_tree"),
            &tx_g.get_prev_txs_tree_root(),
            &tx_g.get_txs_tree_tx_path(),
            &null_leaf_g,
            &tx_g.get_tx_hash(),
            should_enforce,
        )?;

        new_tree_root_g.conditional_enforce_equal(
            cs.ns(|| "enforce next_root"),
            &tx_g.get_next_txs_tree_root(),
            should_enforce,
        )?;

        Ok(())
    }
}