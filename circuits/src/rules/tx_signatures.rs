use crate::transaction::constraints::TransactionGadget;
use algebra::PrimeField;
use crate::{Transaction, TransactionProverData};
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedHash, FieldBasedSignatureScheme};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    fields::fp::FpGadget,
    bits::boolean::Boolean,
};
use std::marker::PhantomData;

pub struct TransactionSignaturesGadget<
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

impl<ConstraintF, T, D, P, H, HG, S, SG, TG> TransactionSignaturesGadget<ConstraintF, T, D, P, H, HG, S, SG, TG>
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
    pub fn conditionally_enforce_signatures_verification<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        tx_g: &TG,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>
    {
        let sigs_g = tx_g.get_signatures();
        let pks_g = tx_g.get_pks();
        let message_to_sign_g = tx_g.get_message_to_sign();

        for (i, (sig_g, pk_g)) in sigs_g.iter().zip(pks_g.iter()).enumerate(){
            //TODO: We don't really know if these signatures and pks come from boxes that are phantom.
            //      In this case we should be able to recognize the phantom ones and enforce the constraint
            //      below accordingly. We can try to move get_signatures() and get_pks() function into
            //      BaseCoinBoxGadget (by discriminating between InputBaseCoinBoxGadget(that will have
            //      the signature) and OutputBaseCoinBoxGadget (that won't have it)).
            //      Or assuming that a phantom signature and a phantom pk will always be the same,
            //      and so we could directly do the phantom check on them here.
            SG::conditionally_enforce_signature_verification(
                cs.ns(|| format!("enforce sig verification {}", i)),
                pk_g,
                sig_g,
                &[message_to_sign_g.clone()],
                should_enforce
            )?;
        }

        Ok(())
    }
}