use algebra::Field;
use primitives::{FieldBasedMerkleTreeParameters, FieldBasedHash, FieldBasedSignatureScheme, FieldBasedMerkleTreePath};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget, FieldBasedMerkleTreePathGadget};
use crate::transaction_box::zen_box::constraints::{InputZenBoxGadget, OutputZenBoxGadget};
use r1cs_std::fields::fp::FpGadget;
use r1cs_std::FromGadget;
use r1cs_core::{ConstraintSystem, SynthesisError};
use crate::transaction::core_transaction::CoreTransactionProverData;
use r1cs_std::alloc::AllocGadget;
use crate::transaction::constraints::TransactionGadget;
use crate::transaction_box::base_coin_box::constraints::BaseCoinBoxGadget;
use r1cs_crypto::merkle_tree::field_based_mht::FieldBasedBinaryMerkleTreePathGadget;
use r1cs_std::bits::boolean::Boolean;
use std::marker::PhantomData;

pub struct CoreTransactionProverDataGadget<
    ConstraintF: Field,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
>
{
    txs_tree_tx_path:   FieldBasedBinaryMerkleTreePathGadget<P, HG, ConstraintF>,
    prev_txs_tree_root: FpGadget<ConstraintF>,
    next_txs_tree_root: FpGadget<ConstraintF>,
    prev_mst_root:      FpGadget<ConstraintF>,
    next_mst_root:      FpGadget<ConstraintF>,
    prev_bvt_root:      FpGadget<ConstraintF>,
    next_bvt_root:      FpGadget<ConstraintF>,
    bvt_batch_size:		usize,

    _hash:              PhantomData<H>,
}

//TODO: Implement TransactionProverDataGadget trait for CoreTransactionProverDataGadget
//TODO: Decide how to handle AllocGadget<T> and FromGadget<D>. Because CoreTransaction contains
//      prover data and prover data contains CoreTransaction
pub struct CoreTransactionGadget<    
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
>
{
    input_gs: 							                Vec<InputZenBoxGadget<ConstraintF, P, H, HG, S, SG>>,
    output_gs: 							                Vec<OutputZenBoxGadget<ConstraintF, P, H, HG, S, SG>>,
    fee_g: 							                    FpGadget<ConstraintF>,
    custom_fields_hash_g: 					            FpGadget<ConstraintF>,
    non_coin_boxes_input_ids_cumulative_hash_g: 		FpGadget<ConstraintF>,
    non_coin_boxes_output_data_cumulative_hash_g: 	    FpGadget<ConstraintF>,
    prover_data_g:					                    CoreTransactionProverDataGadget<ConstraintF, P, H, HG>,
    tx_hash_without_nonces_g: 				            FpGadget<ConstraintF>,
    tx_hash_g:							                FpGadget<ConstraintF>,
    is_phantom:                                         Boolean,
}

impl<ConstraintF, P, H, HG, S, SG> CoreTransactionGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    pub(crate) fn enforce_transaction_hash_without_nonces<CS: ConstraintSystem<ConstraintF>>(
        mut cs:                                         CS,
        input_box_gs:                                   &[InputZenBoxGadget<ConstraintF, P, H, HG, S, SG>],
        output_box_gs:                                  &[OutputZenBoxGadget<ConstraintF, P, H, HG, S, SG>],
        non_coin_boxes_input_ids_cumulative_hash_g:     FpGadget<ConstraintF>,
        non_coin_boxes_output_data_cumulative_hash_g:   FpGadget<ConstraintF>,
        fee_g:                                          FpGadget<ConstraintF>,
        custom_fields_hash_g: 					        FpGadget<ConstraintF>,
    ) -> Result<FpGadget<ConstraintF>, SynthesisError> {

        // H(input_ids)
        let mut hash_inputs = Vec::new();

        input_box_gs.iter().enumerate().for_each(
            |input| {
                hash_inputs.push(input.zen_box.coin_box.id.clone())
            }
        );

        let inputs_digest = HG::check_evaluation_gadget(
            cs.ns(|| "H(input_ids)"),
            hash_inputs.as_slice()
        )?;

        // H(output_data)
        //TODO: Is this the correct way ?
        let mut hash_outputs = Vec::new();

        outputs.iter().enumerate().map(
            |(index, output)| {
                let output_as_fes = output.zen_box.coin_box.to_field_gadget_elements(
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
                inputs_digest, non_coin_boxes_input_ids_cumulative_hash,
                outputs_digest, non_coin_boxes_output_data_cumulative_hash,
                fee, custom_fields_hash
            ]
        )?;

        Ok(tx_hash_without_nonces)
    }

    pub(crate) fn enforce_transaction_hash<CS: ConstraintSystem<ConstraintF>>(
        mut cs:                                         CS,
        input_box_gs:                                   &[InputZenBoxGadget<ConstraintF, P, H, HG, S, SG>],
        message_to_sign_g:                              FpGadget<ConstraintF>,
    ) -> Result<FpGadget<ConstraintF>, SynthesisError>
    {
        //H(input_sigs)
        let mut sigs_digest = Vec::new();

        for (i, input_box_g) in input_box_gs.iter().enumerate() {
            let sig_as_fes = input_box_g.sig.to_field_gadget_elements(
                cs.ns(|| format!("sig_{} to field elements", i))
            )?;
            sigs_digest.extend_from_slice(sig_as_fes.as_slice())
        }

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

impl<ConstraintF, P, H, HG, S, SG> TransactionGadget<ConstraintF, P, H, HG, S, SG>
for CoreTransactionGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn get_coin_inputs(&self) -> Vec<BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>> {
        let mut input_gs = Vec::new();
        for input_box_g in self.input_gs.iter() {
            input_gs.push(input_box_g.zen_box.coin_box.clone())
        }
        input_gs
    }

    fn get_coin_outputs(&self) -> Vec<BaseCoinBoxGadget<ConstraintF, P, H, HG, S, SG>> {
        let mut output_gs = Vec::new();
        for output_box_g in self.input_gs.iter() {
            output_gs.push(output_box_g.coin_box.clone())
        }
        input_gs
    }

    fn get_fee(&self) -> FpGadget<ConstraintF> {
        self.fee_g.clone()
    }

    fn get_signatures(&self) -> Vec<SG> {
        let mut sig_gs = Vec::new();
        for sig_g in self.input_gs.iter() {
            input_gs.push(input_box_g.sig.clone())
        }
        sig_gs
    }

    fn get_pks(&self) -> Vec<SG::PublicKeyGadget> {
        let mut pk_gs = Vec::new();
        for pk_g in self.input_gs.iter() {
            input_gs.push(input_box_g.zen_box.coin_box.pk.clone())
        }
        pk_gs
    }

    fn get_message_to_sign(&self) -> FpGadget<ConstraintF> {
        self.tx_hash_without_nonces_g.clone()
    }

    fn get_tx_hash(&self) -> FpGadget<ConstraintF> {
        self.tx_hash_g.clone()
    }

    fn is_phantom(&self) -> Boolean {
        self.is_phantom.clone()
    }

    fn get_txs_tree_tx_path(&self) -> MHTPG {
        self.prover_data_g.txs_tree_tx_path.clone()
    }

    fn get_prev_txs_tree_root(&self) -> FpGadget<ConstraintF> {
        self.prover_data_g.prev_txs_tree_root.clone()
    }

    fn get_next_txs_tree_root(&self) -> FpGadget<ConstraintF> {
        self.prover_data_g.next_txs_tree_root.clone()
    }

    fn get_prev_mst_root(&self) -> FpGadget<ConstraintF> {
        self.prover_data_g.prev_mst_root.clone()
    }

    fn get_next_mst_root(&self) -> FpGadget<ConstraintF> {
        self.prover_data_g.next_mst_root.clone()
    }

    fn get_prev_bvt_root(&self) -> FpGadget<ConstraintF> {
        self.prover_data_g.prev_bvt_root.clone()
    }

    fn get_next_bvt_root(&self) -> FpGadget<ConstraintF> {
        self.prover_data_g.next_bvt_root.clone()
    }

    fn get_bvt_batch_size(&self) -> usize {
        self.prover_data_g.bvt_batch_size
    }
}

impl<ConstraintF, P, H, HG, S, SG> FromGadget<CoreTransactionProverData<ConstraintF, S, P>, ConstraintF>
    for CoreTransactionGadget<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn from<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        data: CoreTransactionProverData<ConstraintF, S, P>
    ) -> Result<Self, SynthesisError>
    {
        let input_gs = Vec::<InputZenBoxGadget<ConstraintF, P, H, HG, S, SG>>::alloc(
            cs.ns(|| "alloc inputs"),
            data.core_tx.inputs
        )?;

        let output_gs = Vec::<OutputZenBoxGadget<ConstraintF, P, H, HG, S, SG>>::alloc(
            cs.ns(|| "alloc outputs"),
            data.core_tx.outputs
        )?;

        let fee_g = FpGadget::<ConstraintF>::alloc(cs.ns(|| "alloc fee"), data.core_tx.fee)?;

        let custom_fields_hash_g = FpGadget::<ConstraintF>::alloc(
            cs.ns(|| "alloc custom_fields_hash"),
            || Ok(data.core_tx.custom_fields_hash)
        )?;

        let non_coin_boxes_input_ids_cumulative_hash_g = FpGadget::<ConstraintF>::alloc(
            cs.ns(|| "alloc non_coin_boxes_inputs_ids_cumulative_hash"),
            || Ok(data.core_tx.non_coin_boxes_input_ids_cumulative_hash)
        )?;

        let non_coin_boxes_output_data_cumulative_hash_g = FpGadget::<ConstraintF>::alloc(
            cs.ns(|| "alloc non_coin_boxes_output_data_cumulative_hash"),
            || Ok(data.core_tx.non_coin_boxes_output_data_cumulative_hash)
        )?;

        // Implement alloc gadget for CoreTransactionProverDataGadget
        let prover_data_g = CoreTransactionProverDataGadget::alloc(
            cs.ns(|| "alloc core transaction prover data"),
            || Ok(data)
        )?;

        let tx_hash_without_nonces_g = Self::enforce_transaction_hash_without_nonces(
            cs.ns(|| "enforce_tx_hash_without_nonces"),
            input_gs.as_slice(), output_gs.as_slice(),
            non_coin_boxes_input_ids_cumulative_hash_g.clone(),
            non_coin_boxes_output_data_cumulative_hash_g.clone(),
            fee_g.clone(), custom_fields_hash_g.clone()
        )?;

        let tx_hash_g = Self::enforce_transaction_hash(
            cs.ns(|| "enforce_tx_hash"),
            input_gs.as_slice(),
            tx_hash_without_nonces_g.clone(),
        )?;

        let mut new_instance = Self {
            input_gs,
            output_gs,
            fee_g,
            custom_fields_hash_g,
            non_coin_boxes_input_ids_cumulative_hash_g,
            non_coin_boxes_output_data_cumulative_hash_g,
            prover_data_g,
            tx_hash_without_nonces_g,
            tx_hash_g,
            is_phantom: Boolean::Constant(false),
        };

        let phantom_tx = Self::get_phantom(cs.ns(|| "hardcode phantom tx"));
        let is_phantom = new_instance.is_eq(
            cs.ns(|| "is phantom"),
            &phantom_tx
        )?;
        new_instance.is_phantom = is_phantom;

        Ok(new_instance)
    }
}

//TODO: Finish implementing TransactionProverDataGadget for CoreTransactionProverDataGadget
//      (e.g. AllocGadget, ConstantGadget, EqGadget)