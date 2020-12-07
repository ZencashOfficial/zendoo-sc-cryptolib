use algebra::{PrimeField, ToConstraintField, SemanticallyValid, ProjectiveCurve, FromBytes, ToBytes, to_bytes};
use primitives::{signature::schnorr::field_based_schnorr::{
    FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrPk
}, FieldBasedHash, FieldHasher, FieldBasedSignatureScheme};
use crate::base_tx_circuit::{
    constants::TransactionParameters, base_tx_primitives::BaseTxError as Error
};
use std::marker::PhantomData;
use rand::rngs::OsRng;
use serde::{Serialize, Deserialize};


///TODO: I think we need some kind of hash personalization. Let's think about which kind.

////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
pub enum CoinBoxType {
    ZenBox,
    ForgerBox,
    CustomBox,
}

impl From<u8> for CoinBoxType {
    fn from(raw: u8) -> Self {
        match raw {
            0x0 => CoinBoxType::ZenBox,
            0x1 => CoinBoxType::ForgerBox,
            0xff => CoinBoxType::CustomBox,
            _ => unreachable!(),
        }
    }
}

impl From<CoinBoxType> for u8 {
    fn from(box_type: CoinBoxType) -> Self {
        match box_type {
            CoinBoxType::ZenBox => 0x0,
            CoinBoxType::ForgerBox => 0x1,
            CoinBoxType::CustomBox => 0xff,
        }
    }
}

impl<F: PrimeField> ToConstraintField<F> for CoinBoxType {
    fn to_field_elements(&self) -> Result<Vec<F>, Box<dyn std::error::Error>> {
        let raw_type: u8 = self.clone().into();
        [raw_type].to_field_elements()
    }
}

impl Default for CoinBoxType {
    fn default() -> Self {
        CoinBoxType::CustomBox
    }
}

////////////////////////////////////////////////////////////////////////////////////////

#[derive(Default, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(bound(deserialize = "F: PrimeField"))]
pub struct CoinBox<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> {
    pub box_type: CoinBoxType,
    pub amount: u64,
    pub custom_hash: F,
    pub pk: FieldBasedSchnorrPk<G>,
    pub proposition_hash: F,
}

impl<F, G> CoinBox<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>
{
    pub fn new(
        box_type: CoinBoxType,
        amount: u64,
        custom_hash: F,
        pk: FieldBasedSchnorrPk<G>,
        proposition_hash: F,
    ) -> Result<Self, Error>
    {
        let new = Self::new_unchecked(
            box_type, amount,
            custom_hash, pk, proposition_hash
        );
        match new.is_valid() {
            true => Ok(new),
            false => Err(Error::InvalidCoinBox("Attempt to create a semantically invalid coin box".to_owned()))
        }
    }

    pub fn new_unchecked(
        box_type: CoinBoxType,
        amount: u64,
        custom_hash: F,
        pk: FieldBasedSchnorrPk<G>,
        proposition_hash: F,
    ) -> Self
    {
        Self{
            box_type, amount,
            custom_hash, pk, proposition_hash
        }
    }
}

impl <F, G> SemanticallyValid for CoinBox<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>
{
    ///TODO: Expand this ?
    fn is_valid(&self) -> bool {
        self.pk.0.is_valid()
    }
}

impl<F, G> ToConstraintField<F> for CoinBox<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>
{

    fn to_field_elements(&self) -> Result<Vec<F>, Box<dyn std::error::Error>> {

        // Pack box type and amount into one field element
        let mut self_as_fes = {
            let mut fes = self.box_type.to_field_elements().map_err(
                |e| Error::InvalidCoinBox(format!("Unable to read box_type as a field element: {}", e.to_string()))
            )?;
            fes.push(F::read(to_bytes!(self.amount).unwrap().as_slice()).unwrap());
            assert!(fes.len() == 2);
            fes
        };
        self_as_fes.push(self.custom_hash);
        self_as_fes.extend_from_slice(self.pk.0.to_field_elements().map_err(
            |e| Error::InvalidCoinBox(format!("Unable to convert pk into field elements: {}", e.to_string()))
        )?.as_slice());
        self_as_fes.push(self.proposition_hash);
        Ok(self_as_fes)
    }
}

////////////////////////////////////////////////////////////////////////////////////////

#[derive(Default, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(bound(deserialize = "F: PrimeField"))]
pub struct NoncedCoinBox<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>>{
    pub box_data: CoinBox<F, G>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<F>,
}

impl<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> NoncedCoinBox<F, G> {
    pub fn new(box_data: CoinBox<F, G>) -> Self {
        Self {box_data, nonce: None, id: None }
    }

    pub fn update_with_nonce_and_id<H: FieldBasedHash<Data = F>>(
        &mut self,
        _personalization: Option<&[F]>,
        tx_hash_without_nonces: F,
        box_index: u8,
    ) -> Result <(), Error>
    {
        // Compute nonce = truncate(H(tx_hash_without_nonces, box_index), 8) and update self with it
        let box_index_fe = F::read(vec![box_index].as_slice()).unwrap();
        let mut digest = H::init(None);
        digest
            .update(tx_hash_without_nonces)
            .update(box_index_fe);
        let nonce_bytes = to_bytes!(digest.finalize()).unwrap();
        self.nonce = Some(u64::read(&nonce_bytes[..8]).unwrap());

        // Compute id = H(type, value, custom_hash, pk, proposition_hash, nonce)
        // and update self with it. NOTE: We can do this in just 3 hashes if we pack
        // type, value and nonce into one field element (actually it's just enough to
        // pack type and value)
        digest.reset(None);
        let mut box_data_fes = self.box_data.to_field_elements()
            .map_err(|e|
                Error::InvalidCoinBox(format!("Unable to convert CoinBox into field elements: {}", e.to_string()))
            )?;
        let nonce_as_fe = F::read(&nonce_bytes[..8]).unwrap();
        box_data_fes.push(nonce_as_fe);
        box_data_fes.iter().for_each(|&fe| {digest.update(fe);});
        self.id = Some(digest.finalize());
        Ok(())
    }

    pub fn sign<H: FieldBasedHash<Data = F>>(
        &self,
        message_to_sign: F,
        sk: &G::ScalarField
    ) -> Result<FieldBasedSchnorrSignature<F, G>, Error>
    {
        let mut rng = OsRng::default();
        FieldBasedSchnorrSignatureScheme::<F, G, H>::sign(
            &mut rng,
            &self.box_data.pk,
            sk,
            &[message_to_sign]
        ).map_err(|e| Error::InvalidCoinBox(format!("Error while signing coin box {}", e.to_string())))
    }
}

impl<F, G, H> FieldHasher <F, H> for NoncedCoinBox<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>
{
    /// H(NoncedCoinBox) = Box_id
    /// Will be the leaf of the MHT
    fn hash(&self, _personalization: Option<&[F]>) -> Result<F, Box<dyn std::error::Error>> {
        self.id.ok_or(Box::new(Error::InvalidCoinBox("Missing box id".to_owned())))
    }
}

impl<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> SemanticallyValid for NoncedCoinBox<F, G> {
    fn is_valid(&self) -> bool {
        self.box_data.is_valid()
    }
}


////////////////////////////////////////////////////////////////////////////////

#[derive(Default, Clone, Serialize, Deserialize, Eq, PartialEq, Debug)]
#[serde(bound(deserialize = "F: PrimeField"))]
pub struct InputCoinBox<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> {
    pub(crate) box_: NoncedCoinBox<F, G>,
    pub(crate) sig: FieldBasedSchnorrSignature<F, G>
}

pub type OutputCoinBox<F, G> = CoinBox<F, G>;

/// Representation of a transaction able to hold up to `MAX_I_O_BOXES` inputs and outputs.
/// Internally, for Snark friendliness purposes, we will always consider `MAX_I_O_BOXES`,
/// by adding to `inputs`, `num_inputs` default boxes and to `outputs`, `num_outputs`
/// default boxes.
#[derive(Derivative)]
#[derivative(
    PartialEq(bound = "P: TransactionParameters"),
    Eq(bound = "P: TransactionParameters"),
    Debug(bound = "P: TransactionParameters"),
)]
#[derive(Serialize, Deserialize)]
#[serde(bound(deserialize = "F: PrimeField"))]
pub struct CoreTransaction<
    F: PrimeField,
    G: ProjectiveCurve + ToConstraintField<F>,
    H: FieldBasedHash<Data = F>,
    P: TransactionParameters
> {
    /// Coin boxes related data that we manage explicitly in the circuit
    pub(crate) inputs: Vec<InputCoinBox<F, G>>,
    pub(crate) num_inputs: usize,
    pub(crate) outputs: Vec<OutputCoinBox<F, G>>,
    pub(crate) num_outputs: usize,
    pub(crate) fee: u64,
    pub(crate) timestamp: u64, // Probably not needed, planned to be removed

    /// Non coin boxes related data that we don't manage explicitly in the
    /// circuit but that are still needed to construct tx hash
    pub(crate) custom_fields_hash: F,
    pub(crate) non_coin_boxes_input_ids_cumulative_hash: F,
    pub(crate) non_coin_boxes_output_data_cumulative_hash: F,
    pub(crate) non_coin_boxes_input_proofs_cumulative_hash: F,

    /// Will be populated later
    #[serde(skip_serializing_if = "Option::is_none")]
    tx_hash_without_nonces: Option<F>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message_to_sign:        Option<F>,

    #[serde(skip)]
    _parameters: PhantomData<P>,
    #[serde(skip)]
    _hash: PhantomData<H>,
}

impl<F, G, H, P> CoreTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: TransactionParameters
{
    pub fn new(
        inputs: Vec<InputCoinBox<F, G>>,
        outputs: Vec<CoinBox<F, G>>,
        fee: u64,
        timestamp: u64,
        custom_fields_hash: F,
        non_coin_boxes_input_ids_cumulative_hash: F,
        non_coin_boxes_output_data_cumulative_hash: F,
        non_coin_boxes_input_proofs_cumulative_hash: F,
    ) -> Result<Self, Error> {
        let new = Self::new_unchecked(
            inputs, outputs, fee, timestamp,
            custom_fields_hash,
            non_coin_boxes_input_ids_cumulative_hash,
            non_coin_boxes_output_data_cumulative_hash,
            non_coin_boxes_input_proofs_cumulative_hash
        )?;
        match new.is_valid() {
            true => Ok(new),
            false => Err(Error::InvalidTx("Attempt to create a semantically invalid transaction".to_owned()))
        }
    }

    pub fn new_unchecked(
        mut inputs: Vec<InputCoinBox<F, G>>,
        mut outputs: Vec<CoinBox<F, G>>,
        fee: u64,
        timestamp: u64,
        custom_fields_hash: F,
        non_coin_boxes_input_ids_cumulative_hash: F,
        non_coin_boxes_output_data_cumulative_hash: F,
        non_coin_boxes_input_proofs_cumulative_hash: F,
    ) -> Result<Self, Error> {
        let num_inputs = inputs.len();
        assert!(num_inputs >= 1 && num_inputs <= P::MAX_I_O_BOXES);

        let num_outputs = outputs.len();
        assert!(num_outputs >= 1 && num_outputs <= P::MAX_I_O_BOXES);

        // Pad inputs to `MAX_I_O_BOXES`
        inputs.extend_from_slice(vec![InputCoinBox::<F, G>::default(); P::MAX_I_O_BOXES - num_inputs].as_slice());

        // Create output boxes and pad up to `MAX_I_O_BOXES`
        outputs.extend_from_slice(vec![OutputCoinBox::<F, G>::default(); P::MAX_I_O_BOXES - num_outputs].as_slice());

        Ok(Self {
            inputs, num_inputs, outputs, num_outputs, fee, timestamp,
            custom_fields_hash,
            non_coin_boxes_input_ids_cumulative_hash,
            non_coin_boxes_output_data_cumulative_hash,
            non_coin_boxes_input_proofs_cumulative_hash,
            tx_hash_without_nonces: None,
            message_to_sign: None,
            _parameters: PhantomData, _hash: PhantomData
        })
    }

    /// tx_hash_without_nonces = H(
    ///                            H(inputs_ids), non_coin_boxes_input_ids_cumulative_hash,
    ///                            H(outputs_data), non_coin_boxes_output_data_cumulative_hash,
    ///                            timestamp, fee, custom_fields_hash
    ///                           )
    /// NOTE: We include into the hash also padding input/output coin boxes: theoretically,
    /// they do not exist, but if we want to take that into account into the circuit
    /// we should enforce 2 hashes (e.g. for input_ids, we would have H(input_1_id)
    /// if input_2 is null and H(input_1_id, input_2_id) if input_2 is not null, then
    /// we must conditionally select between them); instead, in the circuit, we hash all
    /// a priori, and we enforce this too in the primitive: this allows to halve the cost
    /// of tx hashes inside the circuit.
    pub fn compute_tx_hash_without_nonces(
        &mut self,
    ) -> Result<F, Error> {
        let mut digest = H::init(None);

        if self.tx_hash_without_nonces.is_some() {
            Ok(self.tx_hash_without_nonces.unwrap())
        } else {
            // H(input_ids)
            self.inputs.iter().enumerate().map(
                |(index, input)| {
                    digest.update(input.box_.id.ok_or(Error::InvalidCoinBox(format!("Missing id for box {}", index)))?);
                    Ok(())
                }
            ).collect::<Result<(), Error>>()?;

            let inputs_id_hash = digest.finalize();

            // H(outputs_data)
            //TODO: Is this the correct way ?
            digest.reset(None);

            self.outputs.iter().enumerate().map(
                |(index, output)| {
                    let output_as_fes = output.to_field_elements()
                        .map_err(
                            |e| Error::InvalidCoinBox(format!("Unable to convert output box {} to field elements: {}", index, e.to_string()))
                        )?;
                    output_as_fes.iter().for_each(|&fe| { digest.update(fe); });
                    Ok(())
                }
            ).collect::<Result<(), Error>>()?;

            let outputs_data_hash = digest.finalize();

            //tx_hash_without_nonces
            digest.reset(None);

            digest
                .update(inputs_id_hash)
                .update(self.non_coin_boxes_input_ids_cumulative_hash)
                .update(outputs_data_hash)
                .update(self.non_coin_boxes_output_data_cumulative_hash)
                .update(F::from(self.timestamp))
                .update(F::from(self.fee))
                .update(self.custom_fields_hash);
            let tx_hash_without_nonces = digest.finalize();

            self.tx_hash_without_nonces = Some(tx_hash_without_nonces.clone());
            self.message_to_sign = Some(tx_hash_without_nonces.clone()); //They are the same

            Ok(tx_hash_without_nonces)
        }
    }

    /// message_to_sign == tx_hash_without_nonces currently.
    pub fn compute_message_to_sign(&mut self) -> Result<F, Error>
    {
        if self.message_to_sign.is_some() {
            Ok(self.message_to_sign.unwrap())
        } else {
            self.compute_tx_hash_without_nonces()
        }
    }

    /// Checks performed:
    /// - For each input check that signature is verified;
    /// - Check that inputs_sum - outputs_sum - fee = 0.
    /// Here we need to explicitly differentiate between padding
    /// input/output boxes, because padding signatures/pk will not
    /// be valid and thus would lead to the failure of this function.
    fn verify_tx(
        &self,
    ) -> Result<bool, Error> {
        let mut inputs_sum = 0;
        let mut outputs_sum = 0;
        let mut signatures_verified = true;

        let message_to_sign = self.message_to_sign.ok_or(
            Error::InvalidTx("Unable to verify tx: message_to_sign not computed".to_owned())
        )?;

        for i in 0..self.num_inputs {
            inputs_sum += self.inputs[i].box_.box_data.amount;
            signatures_verified &= FieldBasedSchnorrSignatureScheme::<F, G, H> ::verify(
                &self.inputs[i].box_.box_data.pk,
                &[message_to_sign],
                &self.inputs[i].sig
            ).map_err(|e|
                Error::InvalidTx(format!("Unable to verify signature on tx for input box {}: {}", i, e.to_string()))
            )?;
        }

        for i in 0..self.num_outputs {
            outputs_sum += self.outputs[i].amount;
        }

        Ok(inputs_sum == outputs_sum + self.fee &&
            signatures_verified)
    }
}

impl<F, G, H, P> FieldHasher<F, H> for CoreTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: TransactionParameters
{
    /// TODO: For efficiency reasons, we consider also the padding boxes in computing
    ///       message_to_sign == tx_hash_without_nonces. This means that the tx_hash
    ///       and the signatures will be depending on non-existing boxes. Is this ok ?
    /// tx_hash = H(message_to_sign, H(input_sigs), H(non_coin_boxes_input_proofs_cumulative_hash))
    /// See also `get_tx_hash_without_nonces()` NOTE
    fn hash(&self, _personalization: Option<&[F]>) -> Result<F, Box<dyn std::error::Error>> {

        //H(input_sigs)
        let mut sigs_digest = H::init(None);

        self.inputs.iter().for_each(|input|{
            sigs_digest.update(input.clone().sig.e);
            sigs_digest.update(input.clone().sig.s);
        });
        let sigs_hash = sigs_digest.finalize();

        // message_to_sign
        let message_to_sign = self.message_to_sign.ok_or(
            Error::InvalidTx("Unable to verify tx: message_to_sign not computed".to_owned())
        )?;

        // tx_hash
        Ok(H::init(None)
            .update(message_to_sign)
            .update(sigs_hash)
            .update(self.non_coin_boxes_input_proofs_cumulative_hash)
            .finalize()
        )
    }
}

impl<F, G, H, P> SemanticallyValid for CoreTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: TransactionParameters
{
    fn is_valid(&self) -> bool {
        let mut is_valid = true;

        // Check input boxes semantic validity
        for i in 0..self.num_inputs {
            is_valid &= self.inputs[i].box_.is_valid() && self.inputs[i].sig.is_valid();
        }

        // Check output boxes semantic validity
        for i in 0..self.num_outputs {
            is_valid &= self.outputs[i].is_valid();
        }

        // Verify basic tx rules
        is_valid &= self.verify_tx().unwrap_or(false);

        is_valid
    }
}

impl<F, G, H, P> Default for CoreTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: TransactionParameters
{
    fn default() -> Self {
        Self {
            inputs: vec![InputCoinBox::<F, G>::default(); P::MAX_I_O_BOXES],
            num_inputs: 2,
            outputs: vec![OutputCoinBox::<F, G>::default(); P::MAX_I_O_BOXES],
            num_outputs: 2,
            fee: 0,
            timestamp: 0,
            custom_fields_hash: F::default(),
            non_coin_boxes_input_ids_cumulative_hash: F::default(),
            non_coin_boxes_output_data_cumulative_hash: F::default(),
            non_coin_boxes_input_proofs_cumulative_hash: F::default(),
            tx_hash_without_nonces: None,
            message_to_sign: None,
            _parameters: PhantomData,
            _hash: PhantomData
        }
    }
}

#[cfg(test)]
mod test {
    use algebra::{
        fields::mnt4753::Fr,
        curves::mnt6753::G1Projective,
    };
    use primitives::crh::poseidon::mnt4753::MNT4PoseidonHash;
    use crate::base_tx_circuit::constants::TransactionParameters;
    use super::{InputCoinBox, OutputCoinBox, CoreTransaction};
    //use serde_test::{Token, assert_tokens};

    struct TestTransactionParameters {}

    impl TransactionParameters for TestTransactionParameters
    {
        const MAX_I_O_BOXES: usize = 2;
    }

    type TestCoreTxParams = TestTransactionParameters;
    type TestInputCoinBox = InputCoinBox<Fr, G1Projective>;
    type TestOutputCoinBox = OutputCoinBox<Fr, G1Projective>;
    type TestTransaction = CoreTransaction<Fr, G1Projective, MNT4PoseidonHash, TestCoreTxParams>;

    #[test]
    fn serde_json_coin_box() {
        let json_repr =
            "{\"box_type\":\"CustomBox\",\"amount\":0,\"custom_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"pk\":{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0],\"y\":[13373016969058414402,5670427856875409064,11667651089292452217,1113053963617943770,12325313033510771412,11510260603202358114,3606323059104122008,6452324570546309730,4644558993695221281,1127165286758606988,10756108507984535957,135547536859714],\"z\":[0,0,0,0,0,0,0,0,0,0,0,0]},\"proposition_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]}";

        let coin_box = TestOutputCoinBox::default();
        let serialized = serde_json::to_string(&coin_box).unwrap();
        assert_eq!(json_repr, serialized);

        let coin_box_deserialized: TestOutputCoinBox = serde_json::from_str(&serialized).unwrap();
        assert_eq!(coin_box, coin_box_deserialized);
    }

    #[test]
    fn serde_json_nonced_coin_box() {
        let json_repr = "{\"box_\":{\"box_data\":{\"box_type\":\"CustomBox\",\"amount\":0,\"custom_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"pk\":{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0],\"y\":[13373016969058414402,5670427856875409064,11667651089292452217,1113053963617943770,12325313033510771412,11510260603202358114,3606323059104122008,6452324570546309730,4644558993695221281,1127165286758606988,10756108507984535957,135547536859714],\"z\":[0,0,0,0,0,0,0,0,0,0,0,0]},\"proposition_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]}},\"sig\":{\"e\":[0,0,0,0,0,0,0,0,0,0,0,0],\"s\":[0,0,0,0,0,0,0,0,0,0,0,0]}}";

        let nonced_coin_box = TestInputCoinBox::default();
        let serialized = serde_json::to_string(&nonced_coin_box).unwrap();
        assert_eq!(json_repr, serialized);

        let nonced_coin_box_deserialized: TestInputCoinBox = serde_json::from_str(&serialized).unwrap();
        assert_eq!(nonced_coin_box, nonced_coin_box_deserialized);
    }

    #[test]
    fn serde_json_core_transaction() {
        let json_repr =
            "{\"inputs\":[{\"box_\":{\"box_data\":{\"box_type\":\"CustomBox\",\"amount\":0,\"custom_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"pk\":{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0],\"y\":[13373016969058414402,5670427856875409064,11667651089292452217,1113053963617943770,12325313033510771412,11510260603202358114,3606323059104122008,6452324570546309730,4644558993695221281,1127165286758606988,10756108507984535957,135547536859714],\"z\":[0,0,0,0,0,0,0,0,0,0,0,0]},\"proposition_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]}},\"sig\":{\"e\":[0,0,0,0,0,0,0,0,0,0,0,0],\"s\":[0,0,0,0,0,0,0,0,0,0,0,0]}},{\"box_\":{\"box_data\":{\"box_type\":\"CustomBox\",\"amount\":0,\"custom_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"pk\":{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0],\"y\":[13373016969058414402,5670427856875409064,11667651089292452217,1113053963617943770,12325313033510771412,11510260603202358114,3606323059104122008,6452324570546309730,4644558993695221281,1127165286758606988,10756108507984535957,135547536859714],\"z\":[0,0,0,0,0,0,0,0,0,0,0,0]},\"proposition_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]}},\"sig\":{\"e\":[0,0,0,0,0,0,0,0,0,0,0,0],\"s\":[0,0,0,0,0,0,0,0,0,0,0,0]}}],\"num_inputs\":2,\"outputs\":[{\"box_type\":\"CustomBox\",\"amount\":0,\"custom_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"pk\":{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0],\"y\":[13373016969058414402,5670427856875409064,11667651089292452217,1113053963617943770,12325313033510771412,11510260603202358114,3606323059104122008,6452324570546309730,4644558993695221281,1127165286758606988,10756108507984535957,135547536859714],\"z\":[0,0,0,0,0,0,0,0,0,0,0,0]},\"proposition_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]},{\"box_type\":\"CustomBox\",\"amount\":0,\"custom_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"pk\":{\"x\":[0,0,0,0,0,0,0,0,0,0,0,0],\"y\":[13373016969058414402,5670427856875409064,11667651089292452217,1113053963617943770,12325313033510771412,11510260603202358114,3606323059104122008,6452324570546309730,4644558993695221281,1127165286758606988,10756108507984535957,135547536859714],\"z\":[0,0,0,0,0,0,0,0,0,0,0,0]},\"proposition_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]}],\"num_outputs\":2,\"fee\":0,\"timestamp\":0,\"custom_fields_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"non_coin_boxes_input_ids_cumulative_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"non_coin_boxes_output_data_cumulative_hash\":[0,0,0,0,0,0,0,0,0,0,0,0],\"non_coin_boxes_input_proofs_cumulative_hash\":[0,0,0,0,0,0,0,0,0,0,0,0]}";
        let tx = TestTransaction::default();
        let serialized = serde_json::to_string(&tx).unwrap();
        assert_eq!(serialized, json_repr);
        let tx_deserialized: TestTransaction = serde_json::from_str(&serialized).unwrap();
        assert_eq!(tx, tx_deserialized);
    }
}