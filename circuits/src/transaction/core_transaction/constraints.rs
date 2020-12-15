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

pub struct CoreTransactionProverDataGadget<
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
    MHTPG:       FieldBasedMerkleTreePathGadget<MHTP, H, HG, ConstraintF>,
>
{
    txs_tree_tx_path:   MHTPG,
    prev_txs_tree_root: FpGadget<ConstraintF>,
    next_txs_tree_root: FpGadget<ConstraintF>,
    prev_mst_root:      FpGadget<ConstraintF>,
    next_mst_root:      FpGadget<ConstraintF>,
    prev_bvt_root:      FpGadget<ConstraintF>,
    next_bvt_root:      FpGadget<ConstraintF>,
    bvt_batch_size:		usize
}

pub struct CoreTransactionGadget<    
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
    MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
    MHTPG:       FieldBasedMerkleTreePathGadget<MHTP, H, HG, ConstraintF>,
>
{
    input_gs: 							                Vec<InputZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>>,
    output_gs: 							                Vec<OutputZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>>,
    fee_g: 							                    FpGadget<ConstraintF>,
    custom_fields_hash_g: 					            FpGadget<ConstraintF>,
    non_coin_boxes_input_ids_cumulative_hash_g: 		FpGadget<ConstraintF>,
    non_coin_boxes_output_data_cumulative_hash_g: 	    FpGadget<ConstraintF>,
    prover_data_g:					                    CoreTransactionProverDataGadget<ConstraintF, P, H, HG>,
    tx_hash_without_nonces_g: 				            FpGadget<ConstraintF>,
    tx_hash_g:							                FpGadget<ConstraintF>,
}


impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> TransactionGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
for CoreTransactionGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        MHTPG:       FieldBasedMerkleTreePathGadget<MHTP, H, HG, ConstraintF>,
{
    fn get_coin_inputs(&self) -> Vec<BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>> {
        let mut input_gs = Vec::new();
        for input_box_g in self.input_gs.iter() {
            input_gs.push(input_box_g.zen_box.coin_box.clone())
        }
        input_gs
    }

    fn get_coin_outputs(&self) -> Vec<BaseCoinBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>> {
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
}

impl<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG> FromGadget<CoreTransactionProverData<ConstraintF, S, MHTP>, ConstraintF>
    for CoreTransactionGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
        MHTP:        FieldBasedMerkleTreePath<H = H, Parameters = P>,
        MHTPG:       FieldBasedMerkleTreePathGadget<MHTP, H, HG, ConstraintF>,
{
    fn from<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        data: CoreTransactionProverData<ConstraintF, P, MHTP, MHTPG>
    ) -> Result<Self, SynthesisError>
    {
        //TODO: Alloc gadget for InputZenBoxGadget
        let input_gs = Vec::<InputZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>>::alloc(
            cs.ns(|| "alloc inputs"),
            data.core_tx.inputs
        )?;

        //TODO: Alloc gadget for OutputZenBoxGadget
        let output_gs = Vec::<OutputZenBoxGadget<ConstraintF, P, H, HG, MHTP, S, SG, MHTPG>>::alloc(
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

        let tx_hash_without_nonces_g = Self::enforce_tx_hash_without_nonces(cs, ...)?;
        let tx_hash_g = Self::enforce_tx_hash(cs, ...)?;

        Self {
            input_gs,
            output_gs,
            fee_g,
            custom_fields_hash_g,
            non_coin_boxes_input_ids_cumulative_hash_g,
            non_coin_boxes_output_data_cumulative_hash_g,
            prover_data_g,
            tx_hash_without_nonces_g,
            tx_hash_g
        }
    }
}
