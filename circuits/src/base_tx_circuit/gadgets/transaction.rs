use algebra::{PrimeField, ToConstraintField, ProjectiveCurve, ToBytes, to_bytes, FromBytes};
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
    base_tx_primitives::transaction::{
        CoinBox, NoncedCoinBox, CoreTransaction,
    },
    constants::CoreTransactionParameters,
};
use std::{
    borrow::Borrow, marker::PhantomData,
};
use crate::base_tx_circuit::constants::TransactionParameters;

pub struct CoinBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>
{
    pub box_type: UInt8,
    // For amount it will be useful to keep both bits and field representation
    pub amount_bits: UInt64,
    pub amount: FpGadget<ConstraintF>,
    pub custom_hash: HG::DataGadget,
    pub pk: FieldBasedSchnorrPkGadget<ConstraintF, G, GG>,
    pub proposition_hash: HG::DataGadget,
}

impl<ConstraintF, G, GG, H, HG> Clone for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn clone(&self) -> Self {
        Self {
            box_type: self.box_type.clone(),
            amount_bits: self.amount_bits.clone(),
            amount: self.amount.clone(),
            custom_hash: self.custom_hash.clone(),
            pk: self.pk.clone(),
            proposition_hash: self.proposition_hash.clone()
        }
    }
}

impl<ConstraintF, G, GG, H, HG> Eq for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{}

impl<ConstraintF, G, GG, H, HG> PartialEq for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn eq(&self, other: &Self) -> bool {
        self.box_type == other.box_type &&
            self.amount == other.amount &&
            self.custom_hash == other.custom_hash &&
            self.pk.pk == other.pk.pk &&
            self.proposition_hash == other.proposition_hash
    }
}

impl<ConstraintF, G, GG, H, HG> AllocGadget<CoinBox<ConstraintF, G>, ConstraintF> for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CoinBox<ConstraintF, G>>
    {
        let (box_type, amount, custom_hash, pk, proposition_hash) = match f() {
            Ok(coin_box) => {
                let coin_box = coin_box.borrow().clone();
                (
                    Ok(coin_box.box_type as u8),
                    Ok(coin_box.amount),
                    Ok(coin_box.custom_hash),
                    Ok(coin_box.pk),
                    Ok(coin_box.proposition_hash),
                )
            },
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            )
        };

        let box_type = UInt8::alloc(&mut cs.ns(|| "alloc box_type"), || box_type)?;

        let amount_bits = UInt64::alloc(
            &mut cs.ns(|| "alloc amount"),
            amount.ok()
        )?;

        // TODO: Analyse if it's possible to pass as witness to the circuit directly
        //       a field element corresponding to amount, or if there are security
        //       problems if we don't enforce the actual packing of the amount bits into
        //       a field element.
        let amount = FpGadget::<ConstraintF>::from_bits(
            cs.ns(|| "amount to field gadget"),
            amount_bits.to_bits_le().as_slice()
        )?;

        let custom_hash = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc custom hash"),
            || custom_hash
        )?;

        // It's safe to not perform any check when allocating the pks, considering that they
        // are public and will be committed through a Merkle Tree Hash anyway.
        // TODO: Is this true for our setting too, i.e. the consensus enforces the correctness
        //       of the pks a priori, or we should do it also inside the circuit ?
        let pk = FieldBasedSchnorrPkGadget::<ConstraintF, G, GG>::alloc_without_check(
            &mut cs.ns(|| "alloc pk"),
            || pk
        )?;

        let proposition_hash = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc proposition hash"),
            || proposition_hash
        )?;

        Ok( Self { box_type, amount_bits, amount, custom_hash, pk, proposition_hash } )
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(_cs: CS, _f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CoinBox<ConstraintF, G>> {
        unimplemented!()
    }
}

impl<ConstraintF, G, GG, H, HG> ConstantGadget<CoinBox<ConstraintF, G>, ConstraintF> for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn from_value<CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value: &CoinBox<ConstraintF, G>) -> Self {
        let box_type = UInt8::constant(value.box_type.clone().into());

        let amount_bits = UInt64::constant(value.amount.clone());

        let amount = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode amount as field gadget"),
            &ConstraintF::read(to_bytes!(value.amount.clone()).unwrap().as_slice()).unwrap()
        );

        let custom_hash = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcoded custom hash"),
            &value.custom_hash
        );

        let pk = FieldBasedSchnorrPkGadget::<ConstraintF, G, GG>::from_value(
            &mut cs.ns(|| "hardcode pk"),
            &value.pk,
        );

        let proposition_hash = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode proposition hash"),
            &value.proposition_hash
        );

        Self { box_type, amount_bits, amount, custom_hash, pk, proposition_hash }
    }

    fn get_constant(&self) -> CoinBox<ConstraintF, G> {
        CoinBox::<ConstraintF, G> {
            box_type: self.box_type.get_value().unwrap().into(),
            amount: self.amount_bits.get_value().unwrap(),
            custom_hash: self.custom_hash.get_constant(),
            pk: self.pk.get_constant(),
            proposition_hash: self.proposition_hash.get_constant()
        }
    }
}

impl<ConstraintF, G, GG, H, HG> ToConstraintFieldGadget<ConstraintF> for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    type FieldGadget = FpGadget<ConstraintF>;

    fn to_field_gadget_elements<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS
    ) -> Result<Vec<FpGadget<ConstraintF>>, SynthesisError> {
        // Let's pack box_type and amount into a FpGadget
        let box_info_g = {
            let mut bits = self.box_type.into_bits_le();
            bits.extend_from_slice(self.amount_bits.to_bits_le().as_slice());
            FpGadget::<ConstraintF>::from_bits(
                cs.ns(|| "construct box data"),
                bits.as_slice()
            )
        }?;

        let pk_coords = self.pk.pk.to_field_gadget_elements(cs.ns(|| "pk to field gadget elements"))?;
        let mut box_data = vec![box_info_g, self.custom_hash.clone()];
        box_data.extend_from_slice(pk_coords.as_slice());
        box_data.push(self.proposition_hash.clone());
        Ok(box_data)
    }
}

impl<ConstraintF, G, GG, H, HG> EqGadget<ConstraintF> for CoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn is_eq<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let b1 = self.box_type.is_eq(cs.ns(|| "is_eq_1"), &other.box_type)?;
        let b2 = self.amount.is_eq(cs.ns(|| "is_eq_2"), &other.amount)?;
        let b3 = self.custom_hash.is_eq(cs.ns(|| "is_eq_3"), &other.custom_hash)?;
        let b4 = self.pk.pk.is_eq(cs.ns(|| "is_eq_4"), &other.pk.pk)?;
        let b5 = self.proposition_hash.is_eq(cs.ns(|| "is_eq_5"), &other.proposition_hash)?;

        Boolean::kary_and(
            cs.ns(|| "b1 && b2 && b3 && b4 && b5"),
            &[b1, b2, b3, b4, b5]
        )
    }

    fn conditional_enforce_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.box_type.conditional_enforce_equal(cs.ns(|| "cond_eq_1"), &other.box_type, should_enforce)?;
        self.amount.conditional_enforce_equal(cs.ns(|| "cond_eq_2"), &other.amount, should_enforce)?;
        self.custom_hash.conditional_enforce_equal(cs.ns(|| "cond_eq_3"), &other.custom_hash, should_enforce)?;
        self.pk.pk.conditional_enforce_equal(cs.ns(|| "cond_eq_4"), &other.pk.pk, should_enforce)?;
        self.proposition_hash.conditional_enforce_equal(cs.ns(|| "cond_eq_5"), &other.proposition_hash, should_enforce)?;

        Ok(())
    }

    fn conditional_enforce_not_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.box_type.conditional_enforce_not_equal(cs.ns(|| "cond_neq_1"), &other.box_type, should_enforce)?;
        self.amount.conditional_enforce_not_equal(cs.ns(|| "cond_neq_2"), &other.amount, should_enforce)?;
        self.custom_hash.conditional_enforce_not_equal(cs.ns(|| "cond_neq_3"), &other.custom_hash, should_enforce)?;
        self.pk.pk.conditional_enforce_not_equal(cs.ns(|| "cond_neq_4"), &other.pk.pk, should_enforce)?;
        self.proposition_hash.conditional_enforce_not_equal(cs.ns(|| "cond_neq_5"), &other.proposition_hash, should_enforce)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct NoncedCoinBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>
{
    pub box_data: CoinBoxGadget<ConstraintF, G, GG, H, HG>,
    pub nonce: HG::DataGadget,
    pub id: HG::DataGadget,
}

impl<ConstraintF, G, GG, H, HG> Eq for NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{}

impl<ConstraintF, G, GG, H, HG> PartialEq for NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn eq(&self, other: &Self) -> bool {
        self.box_data == other.box_data &&
        self.nonce == other.nonce &&
        self.id == other.id
    }
}

impl<ConstraintF, G, GG, H, HG> AllocGadget<NoncedCoinBox<ConstraintF, G>, ConstraintF> for NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
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
            T: Borrow<NoncedCoinBox<ConstraintF, G>>
    {
        let (box_data, nonce, id) = match f() {
            Ok(nonced_box) => {
                let nonced_box = nonced_box.borrow().clone();
                (
                    Ok(nonced_box.box_data),
                    Ok(nonced_box.nonce.unwrap()),
                    Ok(nonced_box.id.unwrap())
                )
            },
            _ => (
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
                Err(SynthesisError::AssignmentMissing),
            )
        };

        let box_data = CoinBoxGadget::<ConstraintF, G, GG, H, HG>::alloc(
            cs.ns(|| "alloc box data"),
            || box_data
        )?;

        let nonce_bits = UInt64::alloc(
            &mut cs.ns(|| "alloc nonce"),
            nonce.ok()
        )?;

        // TODO: Analyse if it's possible to pass as witness to the circuit directly
        //       a field element corresponding to nonce, or if there are security
        //       problems if we don't enforce the actual packing of the nonce bits into
        //       a field element.
        let nonce = FpGadget::<ConstraintF>::from_bits(
            cs.ns(|| "nonce to field gadget"),
            nonce_bits.to_bits_le().as_slice()
        )?;

        let id = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc id"),
            || id
        )?;

        Ok(Self { box_data, nonce, id })
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(_cs: CS, _f: F) -> Result<Self, SynthesisError>
        where
            F: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<NoncedCoinBox<ConstraintF, G>>
    {
        unimplemented!()
    }
}

impl<ConstraintF, G, GG, H, HG> ConstantGadget<NoncedCoinBox<ConstraintF, G>, ConstraintF> for NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn from_value<CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value: &NoncedCoinBox<ConstraintF, G>) -> Self {

        let box_data = CoinBoxGadget::<ConstraintF, G, GG, H, HG>::from_value(
            cs.ns(|| "hardcode box_data"),
            &value.box_data
        );

        let nonce = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode nonce as field gadget"),
            &ConstraintF::read(to_bytes!(value.nonce.unwrap()).unwrap().as_slice()).unwrap()
        );

        let id = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode id"),
            &value.id.unwrap()
        );

        Self { box_data, nonce, id }
    }

    fn get_constant(&self) -> NoncedCoinBox<ConstraintF, G> {

        let nonce_bytes = to_bytes!(self.nonce.get_constant()).unwrap();

        NoncedCoinBox::<ConstraintF, G> {
            box_data: self.box_data.get_constant(),
            nonce: Some(u64::read(&nonce_bytes[..8]).unwrap()),
            id: Some(self.id.get_constant())
        }
    }
}

impl<ConstraintF, G, GG, H, HG> NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    pub fn from_coin_box_gadget<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        coin_box_gadget: CoinBoxGadget<ConstraintF, G, GG, H, HG>,
        tx_hash_without_nonces: FpGadget<ConstraintF>,
        box_index: FpGadget<ConstraintF>, //Note: it can be surely hardcoded in the circuit
    ) -> Result<Self, SynthesisError>
    {
        let mut nonced_coin_box_g = NoncedCoinBoxGadget::<ConstraintF, G, GG, H, HG> {
            box_data: coin_box_gadget,
            nonce: FpGadget::<ConstraintF>::zero(&mut cs)?, // Temp value
            id: FpGadget::<ConstraintF>::zero(&mut cs)?, // Temp value
        };

        nonced_coin_box_g.nonce = nonced_coin_box_g.enforce_nonce_calculation(
            cs.ns(|| "enforce nonce for new nonced coin box"),
            tx_hash_without_nonces,
            box_index
        )?;

        nonced_coin_box_g.id = nonced_coin_box_g.enforce_id_calculation(
            cs.ns(|| "enforce id for new nonced coin box")
        )?;

        Ok(nonced_coin_box_g)
    }

    #[inline]
    /// Enforce H(tx_hash_without_nonces, box_index)
    /// PREREQUISITES: Enforce correct `tx_hash_without_nonces`
    pub fn enforce_nonce_calculation<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        tx_hash_without_nonces: FpGadget<ConstraintF>,
        box_index: FpGadget<ConstraintF>, //Note: it can be surely hardcoded in the circuit
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        HG::check_evaluation_gadget(
            cs.ns(|| "enforce box nonce"),
            &[tx_hash_without_nonces, box_index]
        )
    }

    #[inline]
    /// Enforce H(CoinBoxType, value, custom_hash, pk, proposition_hash, nonce)
    /// PREREQUISITES: Enforce correct nonce for `self` box.
    pub fn enforce_id_calculation<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        let mut hash_gadget_input = self.box_data.to_field_gadget_elements(
            cs.ns(|| "box data to field gadget elements")
        )?;
        hash_gadget_input.push(self.nonce.clone());

        HG::check_evaluation_gadget(
            cs.ns(|| "enforce box id"),
            hash_gadget_input.as_slice()
        )
    }
}

impl<ConstraintF, G, GG, H, HG> FieldHasherGadget<H, ConstraintF, HG> for NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    #[inline]
    /// Will be the leaf of the Merkle Tree
    fn enforce_hash<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs: CS,
        _personalization: Option<&[HG::DataGadget]>
    ) -> Result<HG::DataGadget, SynthesisError> {
        self.enforce_id_calculation(cs)
    }
}

impl<ConstraintF, G, GG, H, HG> EqGadget<ConstraintF> for NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
{
    fn is_eq<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let b1 = self.box_data.is_eq(cs.ns(|| "is_eq_1"), &other.box_data)?;
        let b2 = self.nonce.is_eq(cs.ns(|| "is_eq_2"), &other.nonce)?;
        let b3 = self.id.is_eq(cs.ns(|| "is_eq_3"), &other.id)?;

        Boolean::kary_and(
            cs.ns(|| "b1 && b2 && b3"),
            &[b1, b2, b3]
        )
    }

    fn conditional_enforce_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.box_data.conditional_enforce_equal(cs.ns(|| "cond_eq_1"), &other.box_data, should_enforce)?;
        self.nonce.conditional_enforce_equal(cs.ns(|| "cond_eq_2"), &other.nonce, should_enforce)?;
        self.id.conditional_enforce_equal(cs.ns(|| "cond_eq_3"), &other.id, should_enforce)?;

        Ok(())
    }

    fn conditional_enforce_not_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.box_data.conditional_enforce_not_equal(cs.ns(|| "cond_neq_1"), &other.box_data, should_enforce)?;
        self.nonce.conditional_enforce_not_equal(cs.ns(|| "cond_neq_2"), &other.nonce, should_enforce)?;
        self.id.conditional_enforce_not_equal(cs.ns(|| "cond_neq_3"), &other.id, should_enforce)?;

        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub(crate) struct InputCoinBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>
{
    pub(crate) box_: NoncedCoinBoxGadget<ConstraintF, G, GG, H, HG>,
    pub(crate) sig:  FieldBasedSchnorrSigGadget<ConstraintF, G>,
    pub(crate) is_padding: Boolean,
}

#[derive(Clone)]
pub(crate) struct OutputCoinBoxGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>
>
{
    pub(crate) box_: CoinBoxGadget<ConstraintF, G, GG, H, HG>,
    pub(crate) is_padding: Boolean,
}

/// Gadget holding a CoreTransaction. A difference with respect to the primitive is a Boolean
/// coupled with each box, enforced to indicate if that box is a padding box or not.
pub struct CoreTransactionGadget<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    P: CoreTransactionParameters<ConstraintF, G>,
>
{
    /// Coinboxes related data that we manage explicitly in the circuit
    pub(crate) inputs: Vec<InputCoinBoxGadget<ConstraintF, G, GG, H, HG>>,
    pub(crate) outputs: Vec<OutputCoinBoxGadget<ConstraintF, G, GG, H, HG>>,
    pub(crate) fee: FpGadget<ConstraintF>,
    pub(crate) timestamp: FpGadget<ConstraintF>,

    /// Non coinboxes related data that we don't manage explicitly, but
    /// that we need anyway to reconstruct the tx hash
    pub(crate) custom_fields_hash: FpGadget<ConstraintF>,
    pub(crate) non_coin_boxes_input_ids_cumulative_hash: FpGadget<ConstraintF>,
    pub(crate) non_coin_boxes_output_data_cumulative_hash: FpGadget<ConstraintF>,

    /// Will be enforced and populated later
    pub(crate) tx_hash_without_nonces_g:   Option<FpGadget<ConstraintF>>,
    message_to_sign_g:          Option<FpGadget<ConstraintF>>,

    _parameters: PhantomData<P>,
}

impl<ConstraintF, G, GG, H, HG, P> AllocGadget<CoreTransaction<ConstraintF, G, H, P>, ConstraintF>
    for CoreTransactionGadget<ConstraintF, G, GG, H, HG, P>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        P: CoreTransactionParameters<ConstraintF, G>,
{
    /// Allocate input and output boxes, and enforce a Boolean for each of them, indicating if
    /// it's a padding box or not.
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CoreTransaction<ConstraintF, G, H, P>>
    {
        let (
            inputs, outputs,
            fee, timestamp, custom_fields_hash,
            non_coin_boxes_input_ids_cumulative_hash,
            non_coin_boxes_output_data_cumulative_hash
        ) = match f() {
            Ok(tx) => {
                let tx = tx.borrow().clone();
                (
                    Ok(tx.inputs.clone()),
                    Ok(tx.outputs.clone()),
                    Ok(tx.fee),
                    Ok(tx.timestamp),
                    Ok(tx.custom_fields_hash),
                    Ok(tx.non_coin_boxes_input_ids_cumulative_hash),
                    Ok(tx.non_coin_boxes_output_data_cumulative_hash),
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
            )
        };

        let mut input_gs = Vec::with_capacity(<P as TransactionParameters>::MAX_I_O_BOXES);
        let mut output_gs = Vec::with_capacity(<P as TransactionParameters>::MAX_I_O_BOXES);

        let padding_input_box_g = NoncedCoinBoxGadget::<ConstraintF, G, GG, H, HG>::from_value(
            cs.ns(|| "hardcode padding input box"),
            &(P::PADDING_INPUT_BOX.box_)
        );

        let padding_output_box_g = CoinBoxGadget::<ConstraintF, G, GG, H, HG>::from_value(
            cs.ns(|| "hardcode padding output box"),
            &(P::PADDING_OUTPUT_BOX)
        );

        // Alloc input and output boxes that must be exactly `MAX_I_O_BOXES`
        inputs?.into_iter().enumerate().map(|(i, input)| {

            let input_sig_g = FieldBasedSchnorrSigGadget::<ConstraintF, G>::alloc(
                cs.ns(|| format!("alloc_sig_for_nonced_input_box_{}", i)),
                || Ok(input.sig.clone())
            )?;

            let input_g = NoncedCoinBoxGadget::<ConstraintF, G, GG, H, HG>::alloc(
                cs.ns(|| format!("alloc_nonced_input_box_{}", i)),
                || Ok(input.box_)
            )?;

            let is_padding_input = input_g.is_eq(
                cs.ns(|| format!("is_padding_input_{}", i)),
                &padding_input_box_g
            )?;

            input_gs.push(InputCoinBoxGadget::<ConstraintF, G, GG, H, HG>{
                box_: input_g,
                sig: input_sig_g,
                is_padding: is_padding_input
            });

            Ok(())
        }).collect::<Result<(), SynthesisError>>()?;

        assert_eq!(input_gs.len(), <P as TransactionParameters>::MAX_I_O_BOXES);

        outputs?.into_iter().enumerate().map(|(i, output)|{
            let output_g = CoinBoxGadget::<ConstraintF, G, GG, H, HG>::alloc(
                cs.ns(|| format!("alloc_output_box_{}", i)),
                || Ok(output)
            )?;

            let is_padding_output = output_g.is_eq(
                cs.ns(|| format!("is_padding_output_{}", i)),
                &padding_output_box_g
            )?;

            output_gs.push(OutputCoinBoxGadget::<ConstraintF, G, GG, H, HG>{
                box_: output_g,
                is_padding: is_padding_output
            });

            Ok(())
        }).collect::<Result<(), SynthesisError>>()?;

        assert_eq!(output_gs.len(), <P as TransactionParameters>::MAX_I_O_BOXES);

        // Alloc fee by first allocating the u64 bits and then safely packing them into a field element
        let fee = {
            let fee_bits = UInt64::alloc(cs.ns(|| "alloc fee bits"), fee.ok())?;
            FpGadget::<ConstraintF>::from_bits(
                cs.ns(|| "pack fee into a field element"),
                fee_bits.to_bits_le().as_slice()
            )
        }?;

        // Alloc timestamp by first allocating the u64 bits and then safely packing them into a field element
        let timestamp = {
            let timestamp_bits = UInt64::alloc(cs.ns(|| "alloc timestamp bits"), timestamp.ok())?;
            FpGadget::<ConstraintF>::from_bits(
                cs.ns(|| "pack timestamp into a field element"),
                timestamp_bits.to_bits_le().as_slice()
            )
        }?;

        // Alloc non coinboxes related data
        let custom_fields_hash = FpGadget::<ConstraintF>::alloc(
            cs.ns(|| "alloc custom_fields_hash"),
            || custom_fields_hash
        )?;

        let non_coin_boxes_input_ids_cumulative_hash = FpGadget::<ConstraintF>::alloc(
            cs.ns(|| "alloc non_coin_boxes_input_ids_cumulative_hash"),
            || non_coin_boxes_input_ids_cumulative_hash
        )?;

        let non_coin_boxes_output_data_cumulative_hash = FpGadget::<ConstraintF>::alloc(
            cs.ns(|| "alloc non_coin_boxes_output_data_cumulative_hash"),
            || non_coin_boxes_output_data_cumulative_hash
        )?;

        Ok(Self {
            inputs: input_gs,
            outputs: output_gs,
            fee,
            timestamp,
            custom_fields_hash,
            non_coin_boxes_input_ids_cumulative_hash,
            non_coin_boxes_output_data_cumulative_hash,
            tx_hash_without_nonces_g: None,
            message_to_sign_g: None,
            _parameters: PhantomData,
        })
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(_cs: CS, _f: F) -> Result<Self, SynthesisError> where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CoreTransaction<ConstraintF, G, H, P>> {
        unimplemented!()
    }
}

impl<ConstraintF, G, GG, H, HG, P> CoreTransactionGadget<ConstraintF, G, GG, H, HG, P>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        P: CoreTransactionParameters<ConstraintF, G>,
{
    pub fn enforce_tx_hash_without_nonces<CS: ConstraintSystem<ConstraintF>>(
        &mut self,
        mut cs: CS,
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        if self.tx_hash_without_nonces_g.is_some() {
            Ok(self.tx_hash_without_nonces_g.clone().unwrap())
        } else {
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
            //TODO: Is this the correct way ?
            let mut hash_outputs = Vec::new();

            self.outputs.iter().enumerate().map(
                |(index, output)| {
                    let output_as_fes = output.box_.to_field_gadget_elements(
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
                &[
                    inputs_digest, self.non_coin_boxes_input_ids_cumulative_hash.clone(),
                    outputs_digest, self.non_coin_boxes_output_data_cumulative_hash.clone(),
                    self.fee.clone(), self.timestamp.clone(), self.custom_fields_hash.clone()
                ]
            )?;

            self.tx_hash_without_nonces_g = Some(tx_hash_without_nonces.clone());
            self.message_to_sign_g = Some(tx_hash_without_nonces.clone());

            Ok(tx_hash_without_nonces)
        }
    }

    /// message_to_sign == tx_hash_without_nonces
    pub fn enforce_message_to_sign<CS: ConstraintSystem<ConstraintF>>(
        &mut self,
        cs: CS,
    ) -> Result<HG::DataGadget, SynthesisError>
    {
        if self.message_to_sign_g.is_some() {
            Ok(self.message_to_sign_g.clone().unwrap())
        } else {
            self.enforce_tx_hash_without_nonces(cs)
        }
    }

    /// Enforces:
    /// 1) Signatures on `message_to_sign` for input boxes to be correct
    /// 2) inputs_amount - outputs_amount - fee == 0
    /// Will ignore the padding boxes.
    /// PREREQUISITES: `message_to_sign` already enforced
    pub fn conditionally_verify<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError>
    {
        let mut inputs_sum = FpGadget::<ConstraintF>::zero(cs.ns(|| "initialize inputs_sum"))?;
        let mut outputs_sum = inputs_sum.clone();
        let zero = outputs_sum.clone();
        let message_to_sign = self.message_to_sign_g.clone().ok_or(SynthesisError::AssignmentMissing)?;

        self.inputs.iter().enumerate().map(
            |(index, input)| {
                let should_enforce_input = Boolean::and(
                    cs.ns(|| format!("should_enforce_input_sig_{}", index)),
                    should_enforce,
                    &input.is_padding.not()
                )?;

                FieldBasedSchnorrSigVerificationGadget::<ConstraintF, G, GG, H, HG>::conditionally_enforce_signature_verification(
                    cs.ns(|| format!("verify_sig_for_input_{}", index)),
                    &input.box_.box_data.pk,
                    &input.sig,
                    &[message_to_sign.clone()],
                    &should_enforce_input,
                )?;

                let to_add = FpGadget::<ConstraintF>::conditionally_select(
                    cs.ns(|| format!("add_input_amount_or_0_{}", index)),
                    &should_enforce_input,
                    &input.box_.box_data.amount,
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
                let should_enforce_output = Boolean::and(
                    cs.ns(|| format!("should_enforce_output_amount_{}", index)),
                    should_enforce,
                    &output.is_padding.not()
                )?;

                let to_add = FpGadget::<ConstraintF>::conditionally_select(
                    cs.ns(|| format!("add_output_amount_or_0_{}", index)),
                    &should_enforce_output,
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
            .conditional_enforce_equal(
                cs.ns(|| "inputs - outputs - fee == 0"),
                &zero,
                should_enforce
            )?;

        Ok(())
    }
}

impl<ConstraintF, G, GG, H, HG, P> FieldHasherGadget<H, ConstraintF, HG>
for CoreTransactionGadget<ConstraintF, G, GG, H, HG, P>
    where
        ConstraintF: PrimeField,
        G: ProjectiveCurve + ToConstraintField<ConstraintF>,
        GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
        H: FieldBasedHash<Data = ConstraintF>,
        HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        P: CoreTransactionParameters<ConstraintF, G>,
{
    /// PREREQUISITES: `message_to_sign` already enforced
    fn enforce_hash<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
        _personalization: Option<&[<HG as FieldBasedHashGadget<H, ConstraintF>>::DataGadget]>
    ) -> Result<<HG as FieldBasedHashGadget<H, ConstraintF>>::DataGadget, SynthesisError> {

        let message_to_sign = self.message_to_sign_g.clone().ok_or(SynthesisError::AssignmentMissing)?;

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