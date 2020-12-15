use algebra::{Field, Group};
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

pub struct BaseCoinBoxGadget<
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
    MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
>
{
    amount:      FpGadget<ConstraintF>,
    pk:          SG::PublicKeyGadget,
    nonce:       FpGadget<ConstraintF>,
    id:          FpGadget<ConstraintF>,
    custom_hash: FpGadget<ConstraintF>,
    mst_path:	 MHTPG,
    bvt_path:	 MHTPG,
    bvt_leaf:	 FpGadget<ConstraintF>,
}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
where
    ConstraintF: Field,
    P:           FieldBasedMerkleTreePath<H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
    MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
{
    fn get_path_in_mst(&self) -> MHTPG { return self.mst_path.clone(); }
    fn get_path_in_bvt(&self) -> MHTPG { return self.bvt_path.clone(); }
    fn get_leaf_val_in_bvt(&self) -> FpGadget<ConstraintF> { return self.bvt_leaf.clone(); }
}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> TransactionBoxGadget<ConstraintF, BaseCoinBox<ConstraintF, S, MHTP>>
    for BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
{}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> AllocGadget<BaseCoinBox<ConstraintF, S, MHTP>, ConstraintF>
    for BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
{
    fn alloc<F, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BaseCoinBox<ConstraintF, S, MHTP>>
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
            amount_bits.to_bits_le().as_slice()
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

        let mst_path = MHTPG::alloc(
            cs.ns(|| "alloc mst path"),
            || mst_path
        )?;

        let bvt_path = MHTPG::alloc(
            cs.ns(|| "alloc bvt path"),
            || bvt_path
        )?;

        let bvt_leaf = FpGadget::<ConstraintF>::alloc(
            &mut cs.ns(|| "alloc bvt_leaf"),
            || bvt_leaf
        )?;

        Ok( Self { amount, pk, nonce, id, custom_hash, mst_path, bvt_path, bvt_leaf } )
    }

    fn alloc_input<F, T, CS: ConstraintSystem<ConstraintF>>(cs: CS, f: F) -> Result<Self, SynthesisError>
        where
        F: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BaseCoinBox<ConstraintF, S, MHTP>>
    {
        unimplemented!()
    }
}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> ConstantGadget<BaseCoinBox<ConstraintF, S, MHTP>, ConstraintF>
for BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
{
    fn from_value<CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value: &BaseCoinBox<ConstraintF, S, MHTP>) -> Self {

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
        let mst_path = MHTPG::from_value(
            &mut cs.ns(|| "hardcode mst path"),
            &value.mst_path
        );

        // To be implemented in Ginger
        let bvt_path = MHTPG::from_value(
            &mut cs.ns(|| "hardcode bvt path"),
            &value.bvt_path
        );

        let bvt_leaf = FpGadget::<ConstraintF>::from_value(
            &mut cs.ns(|| "hardcode bvt leaf"),
            &value.bvt_leaf
        );

        Ok( Self { amount, pk, nonce, id, custom_hash, mst_path, bvt_path, bvt_leaf } )
    }

    fn get_constant(&self) -> BaseCoinBox<ConstraintF, S, MHTP> {
        Self {
            amount: self.amount.value.unwrap(),
            pk: self.pk.value.unwrap(), // To be implemented in Ginger
            nonce: self.nonce.value.unwrap(),
            id: self.id.value.unwrap(),
            custom_hash: self.custom_hash.value.unwrap(),
            mst_path: self.mst_path.value.unwrap(), // To be implemented in Ginger
            bvt_path: self.bvt_path.value.unwrap(), // To be implemented in Ginger
            bvt_leaf: self.bvt_leaf.value.unwrap(),
        }
    }
}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> Eq
for BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
{}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> PartialEq
for BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
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

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> EqGadget<ConstraintF>
for BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTPG:       FieldBasedMerkleTreePathGadget<P, H, HG, ConstraintF>,
{
    fn is_eq<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let b1 = self.amount.is_eq(cs.ns(|| "is_eq_1"), &other.amount)?;
        let b2 = self.pk.is_eq(cs.ns(|| "is_eq_2"), &other.pk)?; // To be implemented in Ginger
        let b3 = self.nonce.is_eq(cs.ns(|| "is_eq_3"), &other.nonce)?;
        let b4 = self.id.is_eq(cs.ns(|| "is_eq_4"), &other.id)?;
        let b5 = self.custom_hash.is_eq(cs.ns(|| "is_eq_5"), &other.custom_hash)?;

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