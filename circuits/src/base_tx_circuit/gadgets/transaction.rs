use algebra::{PrimeField, ToConstraintField, ProjectiveCurve};
use primitives::FieldBasedHash;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::{
    bits::{
        boolean::Boolean, uint8::UInt8, uint64::UInt64, FromBitsGadget
    },
    alloc::{
        AllocGadget, ConstantGadget
    },
    fields::{
        FieldGadget, fp::FpGadget
    },
    groups::GroupGadget,
    eq::EqGadget,
    select::CondSelectGadget,
    to_field_gadget_vec::ToConstraintFieldGadget,
};
use r1cs_crypto::{FieldBasedHashGadget, signature::schnorr::field_based_schnorr::{
    FieldBasedSchnorrPkGadget, FieldBasedSchnorrSigGadget, FieldBasedSchnorrSigVerificationGadget
}, FieldHasherGadget, FieldBasedSigGadget};
use crate::base_tx_circuit::{
    primitives::transaction::{
        Box, NoncedBox, MAX_I_O_BOXES, BaseTransaction,
    },
    constants::BaseTransactionParameters,
};
use std::{
    borrow::Borrow, marker::PhantomData,
};

//TODO: Maybe we can optimize by removing nonce and id from this struct, even if I suspect
//      the result won't turn out to be elegant.

#[derive(Clone)]
pub struct NoncedBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>{
    pub is_coin_box: Boolean,
    pub box_type: UInt8,
    pub amount: FpGadget<ConstraintF>,
    pub custom_hash: HG::DataGadget,
    pub pk: FieldBasedSchnorrPkGadget<ConstraintF, G, GG>,
    pub proposition_hash: HG::DataGadget,
    pub nonce: HG::DataGadget,
    pub id: HG::DataGadget,
}

impl<ConstraintF, G, GG, H, HG> Eq for NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{}

impl<ConstraintF, G, GG, H, HG> PartialEq for NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn eq(&self, other: &Self) -> bool {
        self.is_coin_box == other.is_coin_box &&
            self.box_type == other.box_type &&
            self.amount == other.amount &&
            self.custom_hash == other.custom_hash &&
            self.pk.pk == other.pk.pk &&
            self.proposition_hash == other.proposition_hash &&
            self.nonce == other.nonce &&
            self.id == other.id
    }
}

impl<ConstraintF, G, GG, H, HG> AllocGadget<NoncedBox<ConstraintF, G>, ConstraintF> for NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<NoncedBox<ConstraintF, G>>
    {
        let (is_coin_box, box_type, amount, custom_hash, pk, proposition_hash, nonce, id) = match f() {
            Ok(nonced_box) => {
                let nonced_box = nonced_box.borrow().clone();
                (
                    Ok(nonced_box.box_data.is_coin_box),
                    Ok(nonced_box.box_data.box_type as u8),
                    Ok(nonced_box.box_data.amount),
                    Ok(nonced_box.box_data.custom_hash),
                    Ok(nonced_box.box_data.pk),
                    Ok(nonced_box.box_data.proposition_hash),
                    Ok(nonced_box.nonce.unwrap()),
                    Ok(nonced_box.id.unwrap())
                )
            },
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            )
        };

        let is_coin_box = Boolean::alloc(&mut cs.ns(|| "alloc is_coin_box"), || is_coin_box)?;

        let box_type = UInt8::alloc(&mut cs.ns(|| "alloc box_type"), || box_type)?;

        let amount = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc amount"),
            || amount
        )?;

        let custom_hash = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc custom hash"),
            || custom_hash
        )?;

        // It's safe to not perform any check when allocating the pks, considering that they
        // are public and will be committed through a Merkle Tree Hash anyway.
        let pk = FieldBasedSchnorrPkGadget::<ConstraintF, G, GG>::alloc_without_check(
            &mut cs.ns(|| "alloc pk"),
            || pk
        )?;

        let proposition_hash = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc proposition hash"),
            || proposition_hash
        )?;

        let nonce = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc nonce"),
            || nonce
        )?;

        let id = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc id"),
            || id
        )?;

        Ok(Self {is_coin_box, box_type, amount, custom_hash, pk, proposition_hash, nonce, id })
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(_cs: CS, _f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<NoncedBox<ConstraintF, G>>
    {
        unimplemented!()
    }
}

impl<ConstraintF, G, GG, H, HG> ConstantGadget<NoncedBox<ConstraintF, G>, ConstraintF> for NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn from_value<CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value: &NoncedBox<ConstraintF, G>) -> Self {
        let is_coin_box = Boolean::constant(value.box_data.is_coin_box);
        let box_type = UInt8::constant(value.box_data.box_type.clone().into());

        let amount = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode amount"),
            &value.box_data.amount
        );

        let custom_hash = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcoded custom hash"),
            &value.box_data.custom_hash
        );

        let pk = FieldBasedSchnorrPkGadget::<ConstraintF, G, GG>::from_value(
            &mut cs.ns(|| "hardcode pk"),
            &value.box_data.pk,
        );

        let proposition_hash = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode proposition hash"),
            &value.box_data.proposition_hash
        );

        let nonce = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode nonce"),
            &value.nonce.unwrap()
        );

        let id = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode id"),
            &value.id.unwrap()
        );

        Self {is_coin_box, box_type, amount, custom_hash, pk, proposition_hash, nonce, id }
    }

    fn get_constant(&self) -> NoncedBox<ConstraintF, G> {
        let box_data = Box::<ConstraintF, G> {
            is_coin_box: self.is_coin_box.get_value().unwrap(),
            box_type: self.box_type.get_value().unwrap().into(),
            amount: self.amount.get_constant(),
            custom_hash: self.custom_hash.get_constant(),
            pk: self.pk.get_constant(),
            proposition_hash: self.proposition_hash.get_constant()
        };
        NoncedBox::<ConstraintF, G> {
            box_data,
            nonce: Some(self.nonce.get_constant()),
            id: Some(self.id.get_constant())
        }
    }
}

impl<ConstraintF, G, GG, H, HG> NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    pub fn get_box_data<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<FpGadget<ConstraintF>>, SynthesisError>
    {
        // Let's group is_coin_box and type into a single FpGadget
        let box_info_g = {
            let mut bits = vec![self.is_coin_box];
            bits.extend_from_slice(self.box_type.into_bits_le().as_slice());
            FpGadget::<ConstraintF>::from_bits(
                cs.ns(|| "construct box info"),
                bits.as_slice()
            )
        }?;

        let pk_coords = self.pk.pk.to_field_gadget_elements()?;
        let mut box_data = vec![box_info_g, self.amount.clone(), self.custom_hash.clone()];
        box_data.extend_from_slice(pk_coords.as_slice());
        box_data.push(self.proposition_hash.clone());
        Ok(box_data)
    }

    pub fn enforce_nonce_calculation<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs: CS,
        tx_hash_without_nonces: FpGadget<ConstraintF>,
        box_index: FpGadget<ConstraintF>, //Note for myself: it can be surely hardcoded
    ) -> Result<(), SynthesisError>
    {
        self.conditional_enforce_nonce_calculation(cs, tx_hash_without_nonces, box_index, &Boolean::Constant(true))
    }

    #[inline]
    /// Enforce H(tx_hash_without_nonces, box_index, pk) == `self.nonce`
    /// PREREQUISITES: Enforce correct `tx_hash_without_nonces`
    pub fn conditional_enforce_nonce_calculation<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        tx_hash_without_nonces: FpGadget<ConstraintF>,
        box_index: FpGadget<ConstraintF>, //Note for myself: it can be surely hardcoded in the circuit
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>
    {
        let mut hash_gadget_input = vec![tx_hash_without_nonces, box_index];
        let pk_coords = self.pk.pk.to_field_gadget_elements()?;
        hash_gadget_input.extend_from_slice(pk_coords.as_slice());

        let nonce = HG::check_evaluation_gadget(
            cs.ns(|| "enforce box nonce"),
            hash_gadget_input.as_slice()
        )?;

        self.nonce.conditional_enforce_equal(cs.ns(|| "enforce nonce"), &nonce, should_enforce)?;

        Ok(())
    }

    pub fn enforce_id_calculation<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs: CS,
    ) -> Result<(), SynthesisError>
    {
        self.conditional_enforce_id_calculation(cs, &Boolean::Constant(true))
    }

    #[inline]
    /// Enforce H(is_coin_box, type, value, custom_hash, pk, proposition_hash, nonce) == `self.id`
    /// PREREQUISITES: Enforce correct nonce for `self` box.
    pub fn conditional_enforce_id_calculation<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>
    {
        let mut hash_gadget_input = self.get_box_data(cs.ns(|| "box data"))?;
        hash_gadget_input.push(self.nonce.clone());

        let id = HG::check_evaluation_gadget(
            cs.ns(|| "enforce box id"),
            hash_gadget_input.as_slice()
        )?;

        self.id.conditional_enforce_equal(cs.ns(|| "enforce id"), &id, should_enforce)?;

        Ok(())
    }
}

impl<ConstraintF, G, GG, H, HG> FieldHasherGadget<H, ConstraintF, HG> for NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    #[inline]
    fn enforce_hash(
        &self,
        _personalization: Option<&[HG::DataGadget]>
    ) -> Result<HG::DataGadget, SynthesisError> {
        Ok(self.id.clone())
    }
}

impl<ConstraintF, G, GG, H, HG> EqGadget<ConstraintF> for NoncedBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn is_eq<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let b0 = self.is_coin_box.is_eq(cs.ns(|| "is_eq_0"), &other.is_coin_box)?;
        let b1 = self.box_type.is_eq(cs.ns(|| "is_eq_1"), &other.box_type)?;
        let b2 = self.amount.is_eq(cs.ns(|| "is_eq_2"), &other.amount)?;
        let b3 = self.custom_hash.is_eq(cs.ns(|| "is_eq_3"), &other.custom_hash)?;
        let b4 = self.pk.pk.is_eq(cs.ns(|| "is_eq_4"), &other.pk.pk)?;
        let b5 = self.proposition_hash.is_eq(cs.ns(|| "is_eq_5"), &other.proposition_hash)?;
        let b6 = self.nonce.is_eq(cs.ns(|| "is_eq_6"), &other.nonce)?;
        let b7 = self.id.is_eq(cs.ns(|| "is_eq_7"), &other.id)?;

        Boolean::kary_and(
            cs.ns(|| "b0 && b1 && b2 && b3 && b4 && b5 && b6 && b7"),
            &[b0, b1, b2, b3, b4, b5, b6, b7]
        )
    }

    fn conditional_enforce_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.is_coin_box.conditional_enforce_equal(cs.ns(|| "cond_eq_0"), &other.is_coin_box, should_enforce)?;
        self.box_type.conditional_enforce_equal(cs.ns(|| "cond_eq_1"), &other.box_type, should_enforce)?;
        self.amount.conditional_enforce_equal(cs.ns(|| "cond_eq_2"), &other.amount, should_enforce)?;
        self.custom_hash.conditional_enforce_equal(cs.ns(|| "cond_eq_3"), &other.custom_hash, should_enforce)?;
        self.pk.pk.conditional_enforce_equal(cs.ns(|| "cond_eq_4"), &other.pk.pk, should_enforce)?;
        self.proposition_hash.conditional_enforce_equal(cs.ns(|| "cond_eq_5"), &other.proposition_hash, should_enforce)?;
        self.nonce.conditional_enforce_equal(cs.ns(|| "cond_eq_6"), &other.nonce, should_enforce)?;
        self.id.conditional_enforce_equal(cs.ns(|| "cond_eq_7"), &other.id, should_enforce)?;

        Ok(())
    }

    fn conditional_enforce_not_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.is_coin_box.conditional_enforce_not_equal(cs.ns(|| "cond_neq_0"), &other.is_coin_box, should_enforce)?;
        self.box_type.conditional_enforce_not_equal(cs.ns(|| "cond_neq_1"), &other.box_type, should_enforce)?;
        self.amount.conditional_enforce_not_equal(cs.ns(|| "cond_neq_2"), &other.amount, should_enforce)?;
        self.custom_hash.conditional_enforce_not_equal(cs.ns(|| "cond_neq_3"), &other.custom_hash, should_enforce)?;
        self.pk.pk.conditional_enforce_not_equal(cs.ns(|| "cond_neq_4"), &other.pk.pk, should_enforce)?;
        self.proposition_hash.conditional_enforce_not_equal(cs.ns(|| "cond_neq_5"), &other.proposition_hash, should_enforce)?;
        self.nonce.conditional_enforce_not_equal(cs.ns(|| "cond_neq_6"), &other.nonce, should_enforce)?;
        self.id.conditional_enforce_not_equal(cs.ns(|| "cond_neq_7"), &other.id, should_enforce)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////

#[derive(Clone)]
pub(crate) struct InputBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>
{
    box_: NoncedBoxGadget<ConstraintF, G, GG, H, HG>,
    sig:  FieldBasedSchnorrSigGadget<ConstraintF, G>,
    is_padding: Boolean,
}

#[derive(Clone)]
pub(crate) struct OutputBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>
{
    box_: NoncedBoxGadget<ConstraintF, G, GG, H, HG>,
    is_padding: Boolean,
}

/// Gadget holding a BaseTransaction. A difference with respect to the primitive is a Boolean
/// coupled with each box, enforced to indicate if that box is a padding box or not.
pub struct BaseTransactionGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    P: BaseTransactionParameters<ConstraintF, G>,
>
{
    inputs: Vec<InputBoxGadget<ConstraintF, G, GG, H, HG>>,
    outputs: Vec<OutputBoxGadget<ConstraintF, G, GG, H, HG>>,
    fee: FpGadget<ConstraintF>,
    timestamp: FpGadget<ConstraintF>,
    _parameters: PhantomData<P>,
}

impl<ConstraintF, G, GG, H, HG, P> AllocGadget<BaseTransaction<ConstraintF, G, H, P>, ConstraintF>
    for BaseTransactionGadget<ConstraintF, G, GG, H, HG, P>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        P: BaseTransactionParameters<ConstraintF, G>,
{
    /// Allocate input and output boxes, and enforce a Boolean for each of them, indicating if
    /// it's a padding box or not.
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BaseTransaction<ConstraintF, G, H, P>>
    {
        let (inputs, outputs, fee, timestamp) = match f() {
            Ok(tx) => {
                let tx = tx.borrow().clone();
                (
                    Ok(tx.inputs.clone()),
                    Ok(tx.outputs.clone()),
                    Ok(tx.fee),
                    Ok(tx.timestamp)
                )
            },
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            )
        };

        let mut input_gs = Vec::with_capacity(MAX_I_O_BOXES);
        let mut output_gs = Vec::with_capacity(MAX_I_O_BOXES);

        let padding_input_box_g = NoncedBoxGadget::<ConstraintF, G, GG, H, HG>::from_value(
            cs.ns(|| "hardcode padding input box"),
            &(P::PADDING_INPUT_BOX.box_)
        );

        let padding_output_box_g = NoncedBoxGadget::<ConstraintF, G, GG, H, HG>::from_value(
            cs.ns(|| "hardcode padding output box"),
            &(P::PADDING_OUTPUT_BOX)
        );

        // Alloc input and output boxes that must be exactly `MAX_I_O_BOXES`
        inputs?.into_iter().enumerate().map(|(i, input)| {

            let input_sig_g = FieldBasedSchnorrSigGadget::<ConstraintF, G>::alloc(
                cs.ns(|| format!("alloc_sig_for_nonced_input_box_{}", i)),
                || Ok(input.sig.clone())
            )?;

            let input_g = NoncedBoxGadget::<ConstraintF, G, GG, H, HG>::alloc(
                cs.ns(|| format!("alloc_nonced_input_box_{}", i)),
                || Ok(input.box_)
            )?;

            let is_padding_input = input_g.is_eq(
                cs.ns(|| format!("is_padding_input_{}", i)),
                &padding_input_box_g
            )?;

            input_gs.push(InputBoxGadget::<ConstraintF, G, GG, H, HG>{
                box_: input_g,
                sig: input_sig_g,
                is_padding: is_padding_input
            });

            Ok(())
        }).collect::<Result<(), SynthesisError>>()?;

        assert_eq!(input_gs.len(), MAX_I_O_BOXES);

        outputs?.into_iter().enumerate().map(|(i, output)|{
            let output_g = NoncedBoxGadget::<ConstraintF, G, GG, H, HG>::alloc(
                cs.ns(|| format!("alloc_nonced_output_box_{}", i)),
                || Ok(output)
            )?;

            let is_padding_output = output_g.is_eq(
                cs.ns(|| format!("is_padding_output_{}", i)),
                &padding_output_box_g
            )?;

            output_gs.push(OutputBoxGadget::<ConstraintF, G, GG, H, HG>{
                box_: output_g,
                is_padding: is_padding_output
            });

            Ok(())
        }).collect::<Result<(), SynthesisError>>()?;

        assert_eq!(output_gs.len(), MAX_I_O_BOXES);

        // Alloc fee
        let fee = FpGadget::<ConstraintF>::alloc(cs.ns(|| "alloc fee"), || fee)?;

        // Alloc timestamp by first allocating the u64 bits and then safely packing them into a field element
        let timestamp = {
            let timestamp_bits = UInt64::alloc(cs.ns(|| "alloc timestamp bits"), timestamp.ok())?;
            FpGadget::<ConstraintF>::from_bits(
                cs.ns(|| "pack timestamp into a field element"),
                timestamp_bits.to_bits_le().as_slice()
            )
        }?;

        Ok(Self {
            inputs: input_gs,
            outputs: output_gs,
            fee,
            timestamp,
            _parameters: PhantomData,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(_cs: CS, _f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BaseTransaction<ConstraintF, G, H, P>> {
        unimplemented!()
    }
}

impl<ConstraintF, G, GG, H, HG, P> BaseTransactionGadget<ConstraintF, G, GG, H, HG, P>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        P: BaseTransactionParameters<ConstraintF, G>,
{
    /// PREREQUISITES: Enforce correct input ids
    pub fn enforce_tx_hash_without_nonces<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        // H(input_ids)
        let mut hash_inputs = Vec::new();

        self.inputs.iter().enumerate().for_each(
            |(_, input)| {
                hash_inputs.push(input.box_.id.clone())
            }
        );

        let inputs_digest = HG::check_evaluation_gadget(
            cs.ns(|| "H(input_ids)"),
            hash_inputs.as_slice()
        )?;

        // H(output_data)
        let mut hash_outputs = Vec::new();

        self.outputs.iter().enumerate().map(
            |(index, output)| {
                let output_as_fes = output.box_.get_box_data(
                    cs.ns(|| format!("get_box_data_output_{}", index))
                )?;
                hash_outputs.extend_from_slice(output_as_fes.as_slice());
                Ok(())
            }
        ).collect::<Result<(), SynthesisError>>()?;

        let outputs_digest = HG::check_evaluation_gadget(
            cs.ns(|| "H(output_data)"),
            hash_outputs.as_slice()
        )?;

        // tx_hash_without_nonces
        let tx_hash_without_nonces = HG::check_evaluation_gadget(
            cs.ns(|| "tx_hash_without_nonces"),
            &[inputs_digest, outputs_digest, self.fee.clone(), self.timestamp.clone()]
        )?;

        Ok(tx_hash_without_nonces)
    }

    /// PREREQUISITES: Enforce correct input ids and output ids
    pub fn enforce_message_to_sign<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        // H(input_ids)
        let mut hash_inputs = Vec::new();

        self.inputs.iter().enumerate().for_each(
            |(_, input)| {
                hash_inputs.push(input.box_.id.clone())
            }
        );

        let inputs_digest = HG::check_evaluation_gadget(
            cs.ns(|| "H(input_ids)"),
            hash_inputs.as_slice()
        )?;

        //H(output_ids)
        let mut hash_outputs = Vec::new();

        self.outputs.iter().enumerate().for_each(
            |(_, output)| {
                hash_outputs.push(output.box_.id.clone())
            }
        );

        let outputs_digest = HG::check_evaluation_gadget(
            cs.ns(|| "H(outputs_ids)"),
            hash_outputs.as_slice()
        )?;

        // message_to_sign
        let message_to_sign = HG::check_evaluation_gadget(
            cs.ns(|| "message_to_sign"),
            &[inputs_digest, outputs_digest, self.fee.clone(), self.timestamp.clone()]
        )?;

        Ok(message_to_sign)
    }

    /// Enforces:
    /// 1) Signatures on `message_to_sign` for input boxes to be correct
    /// 2) inputs_amount - outputs_amount - fee == 0
    /// Will ignore the padding boxes.
    /// PREREQUISITES: `message_to_sign` already enforced
    pub fn verify<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        message_to_sign: FpGadget<ConstraintF>
    ) -> Result<(), SynthesisError>
    {
        let mut inputs_sum = FpGadget::<ConstraintF>::zero(cs.ns(|| "initialize inputs_sum"))?;
        let mut outputs_sum = inputs_sum.clone();
        let zero = outputs_sum.clone();

        self.inputs.iter().enumerate().map(
            |(index, input)| {
                FieldBasedSchnorrSigVerificationGadget::<ConstraintF, G, GG, H, HG>::conditionally_enforce_signature_verification(
                    cs.ns(|| format!("verify_sig_for_input_{}", index)),
                    &input.box_.pk,
                    &input.sig,
                    &[message_to_sign.clone()],
                    &input.is_padding,
                )?;

                let to_add = FpGadget::<ConstraintF>::conditionally_select(
                    cs.ns(|| format!("add_input_amount_or_0_{}", index)),
                    &input.is_padding,
                    &input.box_.amount,
                    &zero,
                )?;

                inputs_sum = inputs_sum.add(
                    cs.ns(|| format!("add_input_value_{}", index)),
                    &to_add,
                )?;
                Ok(())
            }
        ).collect::<Result<(), SynthesisError>>()?;

        self.outputs.iter().enumerate().map(
            |(index, output)| {
                let to_add = FpGadget::<ConstraintF>::conditionally_select(
                    cs.ns(|| format!("add_output_amount_or_0_{}", index)),
                    &output.is_padding,
                    &output.box_.amount,
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
            .sub(cs.ns(|| "inputs - outputs - fee"), &self.fee)?
            .enforce_equal(cs.ns(|| "inputs - outputs - fee == 0"), &zero)?;

        Ok(())
    }

    /// PREREQUISITES: `message_to_sign` already enforced
    fn enforce_tx_hash<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        _personalization: Option<&[HG::DataGadget]>,
        message_to_sign: FpGadget<ConstraintF>,
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        //H(input_sigs)
        let mut sigs_digest = Vec::new();

        self.inputs.iter().for_each(|input|{
            sigs_digest.push(input.sig.e.clone());
            sigs_digest.push(input.sig.s.clone());
        });

        let sigs_hash = HG::check_evaluation_gadget(
            cs.ns(|| "H(input_sigs)"),
            sigs_digest.as_slice()
        )?;

        // tx_hash
        HG::check_evaluation_gadget(
            cs.ns(|| "tx_hash"),
            &[message_to_sign, sigs_hash]
        )
    }
}
