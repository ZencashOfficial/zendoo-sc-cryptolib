use algebra::{PrimeField, ToConstraintField, SemanticallyValid, ProjectiveCurve};
use primitives::{signature::schnorr::field_based_schnorr::{
    FieldBasedSchnorrSignature, FieldBasedSchnorrSignatureScheme, FieldBasedSchnorrPk
}, FieldBasedHash, FieldHasher, FieldBasedSignatureScheme};
use crate::base_tx_circuit::{
    constants::BaseTransactionParameters, BaseTxError as Error
};
use std::marker::PhantomData;
use rand::rngs::OsRng;


///TODO: I think we need some kind of hash personalization. Let's think about which kind.

////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub enum BoxType {
    CoinBox,
    ForgerBox,
    WithdrawalBox,
    CustomBox,
}

impl From<u8> for BoxType {
    fn from(raw: u8) -> Self {
        match raw {
            0x0 => BoxType::CoinBox,
            0x1 => BoxType::ForgerBox,
            0x2 => BoxType::WithdrawalBox,
            0xff => BoxType::CustomBox,
            _ => unreachable!(),
        }
    }
}

impl From<BoxType> for u8 {
    fn from(box_type: BoxType) -> Self {
        match box_type {
            BoxType::CoinBox => 0x0,
            BoxType::ForgerBox => 0x1,
            BoxType::WithdrawalBox => 0x2,
            BoxType::CustomBox => 0xff,
        }
    }
}

impl<F: PrimeField> ToConstraintField<F> for BoxType {
    fn to_field_elements(&self) -> Result<Vec<F>, std::boxed::Box<dyn std::error::Error>> {
        let raw_type: u8 = self.clone().into();
        [raw_type].to_field_elements()
    }
}

////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct Box<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> {
    pub is_coin_box: bool,
    pub box_type: BoxType,
    pub amount: F,
    pub custom_hash: F,
    pub pk: FieldBasedSchnorrPk<G>,
    pub proposition_hash: F,
}

impl<F, G> Box<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>
{
    pub fn new(
        is_coin_box: bool,
        box_type: BoxType,
        amount: F,
        custom_hash: F,
        pk: FieldBasedSchnorrPk<G>,
        proposition_hash: F,
    ) -> Result<Self, Error>
    {
        let new = Self::new_unchecked(
            is_coin_box, box_type, amount,
            custom_hash, pk, proposition_hash
        );
        match new.is_valid() {
            true => Ok(new),
            false => Err(Error::InvalidBox)
        }
    }

    pub fn new_unchecked(
        is_coin_box: bool,
        box_type: BoxType,
        amount: F,
        custom_hash: F,
        pk: FieldBasedSchnorrPk<G>,
        proposition_hash: F,
    ) -> Self
    {
        Self{
            is_coin_box, box_type, amount,
            custom_hash, pk, proposition_hash
        }
    }
}

impl <F, G> SemanticallyValid for Box<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>
{
    fn is_valid(&self) -> bool {
        let box_type_correct = match self.box_type {
            BoxType::CoinBox =>  self.is_coin_box,
            BoxType::ForgerBox => self.is_coin_box,
            BoxType::WithdrawalBox => !self.is_coin_box,
            BoxType::CustomBox => true,
        };
        box_type_correct && self.pk.0.is_valid()
    }
}

impl<F, G> ToConstraintField<F> for Box<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>
{

    fn to_field_elements(&self) -> Result<Vec<F>, std::boxed::Box<dyn std::error::Error>> {
        // Read is_coin_box, box_type, into one field element
        let mut buff = Vec::with_capacity(2);

        buff.push( if self.is_coin_box { 1u8 } else { 0u8 });
        let box_type: u8 = self.box_type.clone().into();
        buff.push(box_type);

        let box_info = {
            let fes = buff.to_field_elements().map_err(|_| Error::InvalidBox)?;
            assert!(fes.len() == 1);
            fes[0]
        };
        let mut self_as_fes = vec![box_info, self.amount, self.custom_hash];
        self_as_fes.extend_from_slice(self.pk.0.to_field_elements().map_err(|_| Error::InvalidBox)?.as_slice());
        self_as_fes.push(self.proposition_hash);
        Ok(self_as_fes)
    }
}

////////////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct NoncedBox<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>>{
    pub box_data: Box<F, G>,
    pub nonce: Option<F>,
    pub id: Option<F>,
}

impl<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> NoncedBox<F, G> {
    pub fn new(box_data: Box<F, G>) -> Self {
        Self {box_data, nonce: None, id: None }
    }

    pub fn update_with_nonce_and_id<H: FieldBasedHash<Data = F>>(
        &mut self,
        _personalization: Option<&[F]>,
        tx_hash_without_nonces: F,
        box_index: u8,
    ) -> Result <(), Error>
    {
        // Compute nonce = H(tx_hash_without_nonces, box_index, pk) and update self with it
        let box_index_fe = F::read(vec![box_index].as_slice()).unwrap();
        let pk = self.box_data.pk.0;
        let mut digest = H::init(None);
        digest
            .update(tx_hash_without_nonces)
            .update(box_index_fe);
        let pk_coords = pk.to_field_elements()
            .map_err(|_| Error::InvalidBox)?;
        pk_coords.iter().for_each(|&coord| { digest.update(coord); });
        self.nonce = Some(digest.finalize());

        // Compute id = H(is_coin_box, type, value, custom_hash, pk, proposition_hash, nonce)
        // and update self with it. NOTE: I changed with respect to Oleksandr document because
        // it's more comfortable
        digest.reset(None);
        let mut box_data_fes = self.box_data.to_field_elements()
            .map_err(|_| Error::InvalidBox)?;
        box_data_fes.push(self.nonce.unwrap());
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
        ).map_err(|_| Error::InvalidBox)
    }
}

impl<F, G, H> FieldHasher <F, H> for NoncedBox<F, G>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>
{
    /// H(Box) = Box_id
    fn hash(&self, _personalization: Option<&[F]>) -> Result<F, std::boxed::Box<dyn std::error::Error>> {
        self.id.ok_or(std::boxed::Box::new(Error::MissingBoxId))
    }
}

impl<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> SemanticallyValid for NoncedBox<F, G> {
    fn is_valid(&self) -> bool {
        self.box_data.is_valid()
    }
}


////////////////////////////////////////////////////////////////////////////////

#[derive(Clone)]
pub struct InputBox<F: PrimeField, G: ProjectiveCurve + ToConstraintField<F>> {
    pub(crate) box_: NoncedBox<F, G>,
    pub(crate) sig: FieldBasedSchnorrSignature<F, G>
}

pub type OutputBox<F, G> = NoncedBox<F, G>;

pub const MAX_I_O_BOXES: usize = 2;

/// Representation of a transaction able to hold up to `MAX_I_O_BOXES` inputs and outputs.
/// Internally, for Snark friendliness purposes, we will always consider `MAX_I_O_BOXES`,
/// by adding to `inputs`, `num_inputs` default boxes and to `outputs`, `num_outputs`
/// default boxes.
pub struct BaseTransaction<
    F: PrimeField,
    G: ProjectiveCurve + ToConstraintField<F>,
    H: FieldBasedHash<Data = F>,
    P: BaseTransactionParameters<F, G>
> {
    pub(crate) inputs: Vec<InputBox<F, G>>,
    pub(crate) num_inputs: usize,
    pub(crate) outputs: Vec<OutputBox<F, G>>,
    pub(crate) num_outputs: usize,
    pub(crate) fee: F,
    pub(crate) timestamp: u64,
    _parameters: PhantomData<P>,
    _hash: PhantomData<H>,
}

impl<F, G, H, P> BaseTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: BaseTransactionParameters<F, G>
{
    pub fn new(
        inputs: Vec<InputBox<F, G>>,
        outputs: Vec<Box<F, G>>,
        fee: F,
        timestamp: u64,
    ) -> Result<Self, Error> {
        let new = Self::new_unchecked(inputs, outputs, fee, timestamp)?;
        match new.is_valid() {
            true => Ok(new),
            false => Err(Error::InvalidTx)
        }
    }

    pub fn new_unchecked(
        inputs: Vec<InputBox<F, G>>,
        outputs: Vec<Box<F, G>>,
        fee: F,
        timestamp: u64,
    ) -> Result<Self, Error> {
        let num_inputs = inputs.len();
        assert!(num_inputs >= 1 && num_inputs <= MAX_I_O_BOXES);

        let num_outputs = outputs.len();
        assert!(num_outputs >= 1 && num_outputs <= MAX_I_O_BOXES);

        // Pad inputs to `MAX_I_O_BOXES`
        let mut inputs = inputs.to_vec();
        inputs.extend_from_slice(
            vec![P::PADDING_INPUT_BOX; MAX_I_O_BOXES - num_inputs].as_slice()
        );

        // Create output boxes and pad up to `MAX_I_O_BOXES`
        let mut outputs = outputs.into_iter().map(|output| {
                NoncedBox::<F, G>::new(output)
            }).collect::<Vec<_>>();
        outputs.extend_from_slice(vec![P::PADDING_OUTPUT_BOX; MAX_I_O_BOXES - num_outputs].as_slice());

        // Compute tx_hash_without_nonces and update non padding output boxes with them. Padding
        // boxes will keep for id and nonce their default values: this will simplify the
        // circuit implementation because allows us to immediately understand if a box is a
        // padding box or not.
        let tx_hash_without_nonces = Self::compute_tx_hash_without_nonces(fee, timestamp, inputs.as_slice(), outputs.as_slice())?;
        for i in 0..num_outputs {
            outputs[i].update_with_nonce_and_id::<H>(None, tx_hash_without_nonces, i as u8)?;
        }

        Ok(Self {inputs, num_inputs, outputs, num_outputs, fee, timestamp, _parameters: PhantomData, _hash: PhantomData})
    }

    /// tx_hash_without_nonces = H(H(inputs_ids), H(outputs_data), timestamp, fee)
    /// NOTE: We include into the hash also padding input/output boxes: theoretically,
    /// they do not exist, but if we want to take that into account into the circuit
    /// we should enforce 2 hashes (e.g. for input_ids, we would have H(input_1_id)
    /// if input_2 is null and H(input_1_id, input_2_id) if input_2 is not null, then
    /// we must conditionally select between them); instead, in the circuit, we hash all
    /// a priori, and we enforce this too in the primitive: this allows to halve the cost
    /// of tx hashes inside the circuit.
    fn compute_tx_hash_without_nonces(
        fee: F,
        timestamp: u64,
        inputs: &[InputBox<F, G>],
        outputs: &[OutputBox<F, G>]
    ) -> Result<F, Error> {
        let mut digest = H::init(None);

        // H(input_ids)
        inputs.iter().enumerate().map(
            |(_, input)| {
                digest.update(input.box_.id.ok_or(Error::MissingBoxId)?);
                Ok(())
            }
        ).collect::<Result<(), Error>>()?;

        let inputs_id_hash = digest.finalize();

        // H(outputs_data)
        digest.reset(None);

        outputs.iter().enumerate().map(
            |(_, output)| {
                let output_as_fes = output.box_data.to_field_elements()
                    .map_err(|_| Error::InvalidBox)?;
                output_as_fes.iter().for_each(|&fe| { digest.update(fe); });
                Ok(())
            }
        ).collect::<Result<(), Error>>()?;

        let outputs_data_hash = digest.finalize();

        //tx_hash_without_nonces
        digest.reset(None);

        digest
            .update(inputs_id_hash)
            .update(outputs_data_hash)
            .update(F::from(timestamp))
            .update(fee);
        Ok(digest.finalize())
    }

    /// message_to_sign = H(H(input_ids), H(output_ids), timestamp, fee)
    /// See also `get_tx_hash_without_nonces()` NOTE.
    pub fn get_message_to_sign(&self) -> Result<F, Error>
    {
        // H(input_ids)
        let mut input_digest = H::init(None);
        self.inputs.iter().enumerate().map(
            |(_, input)| {
                input_digest.update(input.box_.id.ok_or(Error::MissingBoxId)?);
                Ok(())
            }
        ).collect::<Result<(), Error>>()?;
        let input_ids_hash = input_digest.finalize();

        //H(output_ids)
        let mut output_digest = H::init(None);
        self.outputs.iter().enumerate().map(
            |(_, output)| {
                output_digest.update(output.id.ok_or(Error::MissingBoxId)?);
                Ok(())
            }
        ).collect::<Result<(), Error>>()?;
        let output_ids_hash = output_digest.finalize();

        // message_to_sign
        Ok(H::init(None)
            .update(input_ids_hash)
            .update(output_ids_hash)
            .update(F::from(self.timestamp))
            .update(self.fee)
            .finalize())
    }

    /// Checks performed:
    /// - For each input check that signature is verified;
    /// - Check that inputs_sum - outputs_sum - fee = 0.
    /// Here we need to explicitly differentiate between padding
    /// input/output boxes, because padding signatures/pk will not
    /// be valid and thus would lead to the failure of this function.
    pub fn verify_tx(&self) -> Result<bool, Error> {
        let mut inputs_sum = F::zero();
        let mut outputs_sum = F::zero();
        let mut signatures_verified = true;
        let message_to_sign = self.get_message_to_sign()?;

        for i in 0..self.num_inputs {
            if self.inputs[i].box_.box_data.is_coin_box { inputs_sum += &self.inputs[i].box_.box_data.amount }
            signatures_verified &= FieldBasedSchnorrSignatureScheme::<F, G, H> ::verify(
                &self.inputs[i].box_.box_data.pk,
                &[message_to_sign],
                &self.inputs[i].sig
            ).map_err(|_| Error::InvalidTx)?;
        }

        for i in 0..self.num_outputs {
            if self.outputs[i].box_data.is_coin_box { outputs_sum += &self.outputs[i].box_data.amount }
        }

        Ok(inputs_sum - &outputs_sum - &self.fee == F::zero() &&
            signatures_verified)
    }
}

impl<F, G, H, P> FieldHasher<F, H> for BaseTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: BaseTransactionParameters<F, G>
{
    /// tx_hash = H(message_to_sign, H(input_sigs))
    /// See also `get_tx_hash_without_nonces()` NOTE
    fn hash(&self, _personalization: Option<&[F]>) -> Result<F, std::boxed::Box<dyn std::error::Error>> {

        //H(input_sigs)
        let mut sigs_digest = H::init(None);

        self.inputs.iter().for_each(|input|{
            sigs_digest.update(input.clone().sig.e);
            sigs_digest.update(input.clone().sig.s);
        });
        let sigs_hash = sigs_digest.finalize();

        // message_to_sign
        let message_to_sign = self.get_message_to_sign()?;

        // tx_hash
        Ok(H::init(None)
            .update(message_to_sign)
            .update(sigs_hash)
            .finalize()
        )
    }
}

impl<F, G, H, P> SemanticallyValid for BaseTransaction<F, G, H, P>
    where
        F: PrimeField,
        G: ProjectiveCurve + ToConstraintField<F>,
        H: FieldBasedHash<Data = F>,
        P: BaseTransactionParameters<F, G>
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