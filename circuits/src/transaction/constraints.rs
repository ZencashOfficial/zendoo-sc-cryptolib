use algebra::Field;
use crate::{Transaction, TransactionProverData, TransactionStates};
use r1cs_std::alloc::{AllocGadget, ConstantGadget};
use r1cs_std::eq::EqGadget;
use crate::transaction_box::base_coin_box::constraints::BaseCoinBoxGadget;
use r1cs_std::fields::fp::FpGadget;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_crypto::signature::schnorr::field_based_schnorr::{
    FieldBasedSchnorrSigVerificationGadget, FieldBasedSchnorrPkGadget
};
use r1cs_std::bits::boolean::Boolean;
use primitives::{FieldBasedMerkleTreePath, FieldBasedHash, FieldBasedSignatureScheme, FieldBasedMerkleTreeParameters};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget, FieldBasedMerkleTreePathGadget};
use r1cs_std::FromGadget;
use r1cs_crypto::merkle_tree::field_based_mht::FieldBasedBinaryMerkleTreePathGadget;

pub trait TransactionGadget<
    ConstraintF: Field,
    T:           Transaction,
    D:           TransactionProverData<T>,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
>:
    AllocGadget<T, ConstraintF> +
    ConstantGadget<T, ConstraintF> +
    FromGadget<D, ConstraintF> +
    EqGadget<ConstraintF> +
    Eq +
    PartialEq
{
    fn get_coin_inputs(&self) -> Vec<BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>>;
    fn get_coin_outputs(&self) -> Vec<BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>>;
    fn get_fee(&self) -> FpGadget<ConstraintF>;
    fn get_signatures(&self) -> Vec<SG>;
    fn get_pks(&self) -> Vec<SG::PublicKeyGadget>;
    fn get_message_to_sign(&self) -> FpGadget<ConstraintF>;
    fn get_tx_hash(&self) -> FpGadget<ConstraintF>;
    fn get_phantom<CS: ConstraintSystem<ConstraintF>>() -> Self {
        let phantom_tx = T::default();
        <Self as ConstantGadget<T, ConstraintF>>::from_value(cs, &phantom_tx)
    }

    // These functions are generic enough to be put in TransactionGadget. Otherwise, we
    // can always make a trait, let TransactionGadget implement it, and templatize the
    // corresponding enforcer gadget with that Trait.
    fn get_txs_tree_tx_path(&self) -> FieldBasedBinaryMerkleTreePathGadget<P, HG, ConstraintF>;
    fn get_prev_txs_tree_root(&self) -> FpGadget<ConstraintF>;
    fn get_next_txs_tree_root(&self) -> FpGadget<ConstraintF>;
    fn get_prev_mst_root(&self) -> FpGadget<ConstraintF>;
    fn get_next_mst_root(&self) -> FpGadget<ConstraintF>;
    fn get_prev_bvt_root(&self) -> FpGadget<ConstraintF>;
    fn get_next_bvt_root(&self) -> FpGadget<ConstraintF>;

    fn conditionally_enforce<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> where Self: Sized
    {

        // Enforce correct balance
        TxBalanceGadget::conditionally_enforce_balance(
            cs.ns(|| "enforce balance"), self, should_enforce
        )?;

        // Enforce correct input signatures
        TxSignaturesGadget::conditionally_enforce_signatures(
            cs.ns(|| "enforce signatures"), self, should_enforce
        )?;

        // Enforce tx hash belongs in block tx tree
        TxInTreeGadget::enforce_append_tx_in_tree(
            cs.ns(|| "enforce tx in tree"), self, should_enforce
        )?;

        // Enforce MST and BVT transition for input and output boxes
        BoxesStateTransitionGadget::enforce_state_transition(
            cs.ns(|| "enforce mst and bvt state transition"), self, should_enforce
        )?;

        Ok(())
    }
}

pub trait TransactionProverDataGadget<
    ConstraintF: Field,
    T: Transaction,
    D: TransactionProverData<T>
>: AllocGadget<D, ConstraintF> + ConstantGadget<D, ConstraintF> + EqGadget<ConstraintF> {}

////////////////////

pub struct TransactionStatesGadget<ConstraintF: Field>(pub Vec<FpGadget<ConstraintF>>);

impl<ConstraintF: Field> AllocGadget<TransactionStates<ConstraintF>, ConstraintF> for TransactionStatesGadget<ConstraintF> {
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<TransactionStates<ConstraintF>>
    {
        Vec::<FpGadget<ConstraintF>>::alloc(cs.ns(|| "alloc states"), Ok(f()?.borrow().0))
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<TransactionStates<ConstraintF>>
    {
        Vec::<FpGadget<ConstraintF>>::alloc_input(cs.ns(|| "alloc input states"), Ok(f()?.borrow().0))
    }
}

//TODO: Implement ConstantGadget, EqGadget, CondSelectGadget like in the document

///////////////////

pub struct TransactionTransitionsStatesGadget<ConstraintF: Field> {
    start_states:	TransactionStatesGadget<ConstraintF>,
    end_states:	    TransactionStatesGadget<ConstraintF>,
}

//TODO: Implement ConstantGadget, EqGadget, CondSelectGadget like in the document

//////////

pub trait TxStatesWrapper<
    ConstraintF: Field,
    T:           Transaction,
    D:           TransactionProverData<T>,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    TG:          TransactionGadget<ConstraintF, T, D, P, H, HG, S, SG>
>
{
    fn get_state_transitions_gadgets(tx_g: &TG) -> TransactionTransitionsStatesGadget<ConstraintF>;
}