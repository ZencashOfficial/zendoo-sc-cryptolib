use algebra::{PrimeField, Group, ToBytes};
use r1cs_std::groups::GroupGadget;
use r1cs_crypto::{FieldBasedMerkleTreePathGadget, FieldBasedHashGadget, FieldBasedSigGadget};
use primitives::{FieldBasedMerkleTreePath, FieldBasedHash, FieldBasedSignatureScheme, FieldBasedMerkleTreeParameters};
use r1cs_std::bits::uint64::UInt64;
use r1cs_crypto::signature::schnorr::field_based_schnorr::FieldBasedSchnorrPkGadget;
use r1cs_std::fields::fp::FpGadget;
use r1cs_std::alloc::{AllocGadget, ConstantGadget};
use crate::transaction_box::base_coin_box::BaseCoinBox;
use r1cs_core::{ConstraintSystem, SynthesisError};
use r1cs_std::FromBitsGadget;
use r1cs_std::eq::EqGadget;
use r1cs_std::bits::boolean::Boolean;
use crate::transaction_box::constraints::TransactionBoxGadget;
use r1cs_crypto::merkle_tree::field_based_mht::FieldBasedBinaryMerkleTreePathGadget;
use r1cs_std::to_field_gadget_vec::ToConstraintFieldGadget;
use std::borrow::Borrow;

//TODO: Add missing fields ? (sync with actual SDK)
pub struct BaseCoinBoxGadget<
    ConstraintF: PrimeField,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
>
{
    pub amount:      FpGadget<ConstraintF>,
    pub pk:          SG::PublicKeyGadget,
    pub nonce:       FpGadget<ConstraintF>,
    pub id:          FpGadget<ConstraintF>,
    pub custom_hash: FpGadget<ConstraintF>,
    pub mst_path:	 FieldBasedBinaryMerkleTreePathGadget<P, HG, ConstraintF>,
    pub bvt_path:	 FieldBasedBinaryMerkleTreePathGadget<P, HG, ConstraintF>,
    pub bvt_leaf:	 FpGadget<ConstraintF>,
    pub is_phantom:  Boolean,
}

//TODO: The getters won't return a cloned value, but return a reference. Rust smart pointers
//      like Rc or Cow are good for this purpose.
impl<ConstraintF, P, H, HG, S, SG> BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
where
    ConstraintF: PrimeField,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    pub fn get_path_in_mst(&self) -> FieldBasedBinaryMerkleTreePathGadget<P, HG, ConstraintF> { return self.mst_path.clone(); }
    pub fn get_path_in_bvt(&self) -> FieldBasedBinaryMerkleTreePathGadget<P, HG, ConstraintF> { return self.bvt_path.clone(); }
    pub fn get_leaf_val_in_bvt(&self) -> FpGadget<ConstraintF> { return self.bvt_leaf.clone(); }
}

// TODO: GINGER: Default is not implemented for FieldBasedMerkleTreeParameters and FieldBasedSignatureScheme
impl<ConstraintF, P, H, HG, S, SG> TransactionBoxGadget<ConstraintF, BaseCoinBox<ConstraintF, S, P>>
    for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn is_phantom(&self) -> Boolean {
        self.is_phantom.clone()
    }
}

impl<ConstraintF, P, H, HG, S, SG> AllocGadget<BaseCoinBox<ConstraintF, S, P>, ConstraintF>
    for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BaseCoinBox<ConstraintF, S, P>>
    {
        let (amount, pk, nonce, id, custom_hash, mst_path, bvt_path, bvt_leaf) = match f() {
            Ok(coin_box) => {
                let coin_box = coin_box.borrow().clone();
                (
                    Ok(coin_box.amount),
                    Ok(coin_box.pk),
                    Ok(coin_box.nonce),
                    Ok(coin_box.id),
                    Ok(coin_box.custom_hash),
                    Ok(coin_box.mst_path),
                    Ok(coin_box.bvt_path),
                    Ok(coin_box.bvt_leaf),
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

        // It's safe to not perform any check when allocating the pks, considering that they
        // are public and will be committed through a Merkle Tree Hash anyway.
        // TODO: Is this true for our setting too, i.e. the consensus enforces the correctness
        //       of the pks a priori, or we should do it also inside the circuit ?
        let pk = SG::PublicKeyGadget::alloc_without_check(
            &mut cs.ns(|| "alloc pk"),
            || pk
        )?;

        let id = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc id"),
            || id
        )?;

        let custom_hash = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc custom hash"),
            || custom_hash
        )?;

        let mst_path = FieldBasedBinaryMerkleTreePathGadget::<P, HG, ConstraintF>::alloc(
            cs.ns(|| "alloc mst path"),
            || mst_path
        )?;

        let bvt_path = FieldBasedBinaryMerkleTreePathGadget::<P, HG, ConstraintF>::alloc(
            cs.ns(|| "alloc bvt path"),
            || bvt_path
        )?;

        let bvt_leaf = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc bvt_leaf"),
            || bvt_leaf
        )?;

        let mut new_instance = Self {
            amount, pk, nonce, id, custom_hash, mst_path, bvt_path, bvt_leaf, is_phantom: Boolean::Constant(false)
        };
        let phantom_self = Self::get_phantom(cs.ns(|| "hardcode phantom box"));
        let is_phantom = new_instance.is_eq(cs.ns(|| "is phantom"), &phantom_self)?;
        new_instance.is_phantom = is_phantom;

        Ok(new_instance)
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BaseCoinBox<ConstraintF, S, P>>
    {
        unimplemented!()
    }
}

impl<ConstraintF, P, H, HG, S, SG> ConstantGadget<BaseCoinBox<ConstraintF, S, P>, ConstraintF>
for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn from_value<CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value: &BaseCoinBox<ConstraintF, S, P>) -> Self {

        let amount = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode amount as field gadget"),
            &ConstraintF::read(to_bytes!(value.amount.clone()).unwrap().as_slice()).unwrap()
        );

        let nonce = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode nonce as field gadget"),
            &ConstraintF::read(to_bytes!(value.nonce.clone()).unwrap().as_slice()).unwrap()
        );

        // To be implemented in Ginger
        let pk = SG::PublicKeyGadget::from_value(
            &mut cs.ns(|| "hardcode pk"),
            &value.pk,
        );

        let id = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode id"),
            &value.id
        );

        let custom_hash = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode custom hash"),
            &value.custom_hash
        );

        // To be implemented in Ginger
        let mst_path = FieldBasedBinaryMerkleTreePathGadget::<P, HG, ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode mst path"),
            &value.mst_path
        );

        // To be implemented in Ginger
        let bvt_path = FieldBasedBinaryMerkleTreePathGadget::<P, HG, ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode bvt path"),
            &value.bvt_path
        );

        let bvt_leaf = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode bvt leaf"),
            &value.bvt_leaf
        );

        Self { amount, pk, nonce, id, custom_hash, mst_path, bvt_path, bvt_leaf, is_phantom: Boolean::Constant(false) }
    }

    fn get_constant(&self) -> BaseCoinBox<ConstraintF, S, P> {
        BaseCoinBox {
            amount: self.amount.value.unwrap(),
            pk: self.pk.get_constant().unwrap(), // TODO: To be implemented in Ginger
            nonce: self.nonce.value.unwrap(),
            id: self.id.value.unwrap(),
            custom_hash: self.custom_hash.value.unwrap(),
            mst_path: self.mst_path.get_constant().unwrap(), // TODO: To be implemented in Ginger
            bvt_path: self.bvt_path.get_constant().unwrap(), // TODO: To be implemented in Ginger
            bvt_leaf: self.bvt_leaf.value.unwrap()
        }
    }
}

impl<ConstraintF, P, H, HG, S, SG> Eq for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{}

impl<ConstraintF, P, H, HG, S, SG> PartialEq for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn eq(&self, other: &Self) -> bool {
        self.amount == other.amount &&
            self.pk == other.pk &&
            self.nonce == other.nonce &&
            self.id == other.id &&
            self.custom_hash == other.custom_hash &&
            self.mst_path == other.mst_path &&
            self.bvt_path == other.bvt_path &&
            self.bvt_leaf == other.bvt_leaf
    }
}

impl<ConstraintF, P, H, HG, S, SG> EqGadget<ConstraintF> for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn is_eq<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let b1 = self.amount.is_eq(cs.ns(|| "is_eq_1"), &other.amount)?;
        let b2 = self.pk.is_eq(cs.ns(|| "is_eq_2"), &other.pk)?; // To be implemented in Ginger
        let b3 = self.nonce.is_eq(cs.ns(|| "is_eq_3"), &other.nonce)?;
        let b4 = self.id.is_eq(cs.ns(|| "is_eq_4"), &other.id)?;
        let b5 = self.custom_hash.is_eq(cs.ns(|| "is_eq_5"), &other.custom_hash)?;
        let b6 = self.mst_path.is_eq(cs.ns(|| "is_eq_6"), &other.mst_path)?;
        let b7 = self.bvt_path.is_eq(cs.ns(|| "is_eq_7"), &other.bvt_path)?;
        let b8 = self.bvt_leaf.is_eq(cs.ns(|| "is_eq_8"), &other.bvt_leaf)?;

        Boolean::kary_and(
            cs.ns(|| "b1 && b2 && b3 && b4 && b5 && b6 && b7 && b8"),
            &[b1, b2, b3, b4, b5, b6, b7, b8]
        )
    }

    //TODO
    fn conditional_enforce_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.box_type.conditional_enforce_equal(cs.ns(|| "cond_eq_1"), &other.box_type, should_enforce)?;
        self.amount.conditional_enforce_equal(cs.ns(|| "cond_eq_2"), &other.amount, should_enforce)?;
        self.custom_hash.conditional_enforce_equal(cs.ns(|| "cond_eq_3"), &other.custom_hash, should_enforce)?;
        self.pk.pk.conditional_enforce_equal(cs.ns(|| "cond_eq_4"), &other.pk.pk, should_enforce)?;
        self.proposition_hash.conditional_enforce_equal(cs.ns(|| "cond_eq_5"), &other.proposition_hash, should_enforce)?;

        Ok(())
    }

    //TODO
    fn conditional_enforce_not_equal<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self, should_enforce: &Boolean) -> Result<(), SynthesisError> {
        self.box_type.conditional_enforce_not_equal(cs.ns(|| "cond_neq_1"), &other.box_type, should_enforce)?;
        self.amount.conditional_enforce_not_equal(cs.ns(|| "cond_neq_2"), &other.amount, should_enforce)?;
        self.custom_hash.conditional_enforce_not_equal(cs.ns(|| "cond_neq_3"), &other.custom_hash, should_enforce)?;
        self.pk.pk.conditional_enforce_not_equal(cs.ns(|| "cond_neq_4"), &other.pk.pk, should_enforce)?;
        self.proposition_hash.conditional_enforce_not_equal(cs.ns(|| "cond_neq_5"), &other.proposition_hash, should_enforce)?;

        Ok(())
    }
}

impl<ConstraintF, P, H, HG, S, SG> ToConstraintFieldGadget<ConstraintF> for BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: PrimeField,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    type FieldGadget = FpGadget<ConstraintF>;

    fn to_field_gadget_elements<CS: ConstraintSystem<ConstraintF>>(
        &self,
        cs: CS
    ) -> Result<Vec<Self::FieldGadget>, SynthesisError> {
        let mut self_as_fe = vec![self.amount.clone()];
        let pk_as_fe = self.pk.to_field_gadget_elements(cs)?;
        self_as_fe.extend_from_slice(pk_as_fe.as_slice());
        self_as_fe.push(self.custom_hash.clone());
        Ok(self_as_fe)
    }
}