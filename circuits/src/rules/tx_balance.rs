use crate::transaction::constraints::TransactionGadget;
use algebra::PrimeField;
use crate::{Transaction, TransactionProverData};
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedHash, FieldBasedSignatureScheme};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget};
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    fields::{
        fp::FpGadget, FieldGadget,
    },
    bits::boolean::Boolean,
};
use std::marker::PhantomData;
use r1cs_std::eq::EqGadget;
use crate::transaction_box::constraints::TransactionBoxGadget;
use r1cs_std::select::CondSelectGadget;

pub struct TransactionBalanceGadget<
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

impl<ConstraintF, T, D, P, H, HG, S, SG, TG> TransactionBalanceGadget<ConstraintF, T, D, P, H, HG, S, SG, TG>
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
    pub fn conditionally_enforce_balance<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        tx_g: &TG,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>
    {
        let input_boxes_g = tx_g.get_coin_inputs();
        let output_boxes_g = tx_g.get_coin_outputs();
        let fee_g = tx_g.get_fee();

        let mut inputs_sum = FpGadget::<ConstraintF>::zero(cs.ns(|| "initialize inputs_sum"))?;
        let mut outputs_sum = inputs_sum.clone();
        let zero = outputs_sum.clone();

        input_boxes_g.iter().enumerate().map(
            |(index, input)| {
                let should_enforce_input = Boolean::and(
                    cs.ns(|| format!("should_enforce_input_amount_{}", index)),
                    should_enforce,
                    &input.is_phantom().not()
                )?;

                let to_add = FpGadget::<ConstraintF>::conditionally_select(
                    cs.ns(|| format!("add_input_amount_or_0_{}", index)),
                    &should_enforce_input,
                    &input.amount,
                    &zero,
                )?;

                inputs_sum = inputs_sum.add(
                    cs.ns(|| format!("add_input_value_{}", index)),
                    &to_add,
                )?;
                Ok(())
            }
        ).collect::<Result<(), SynthesisError>>()?;

        output_boxes_g.iter().enumerate().map(
            |(index, output)| {
                let should_enforce_output = Boolean::and(
                    cs.ns(|| format!("should_enforce_output_amount_{}", index)),
                    should_enforce,
                    &output.is_phantom().not()
                )?;

                let to_add = FpGadget::<ConstraintF>::conditionally_select(
                    cs.ns(|| format!("add_output_amount_or_0_{}", index)),
                    &should_enforce_output,
                    &output.amount,
                    &zero,
                )?;

                outputs_sum = outputs_sum.add(
                    cs.ns(|| format!("add_output_value_{}", index)),
                    &to_add
                )?;
                Ok(())
            }
        ).collect::<Result<(), SynthesisError>>()?;

        inputs_sum
            .sub(cs.ns(|| "inputs - outputs"), &outputs_sum)?
            .sub(cs.ns(|| "inputs - outputs - fee"), &fee_g)?
            .conditional_enforce_equal(
                cs.ns(|| "inputs - outputs - fee == 0"),
                &zero,
                should_enforce
            )?;
        Ok(())
    }
}