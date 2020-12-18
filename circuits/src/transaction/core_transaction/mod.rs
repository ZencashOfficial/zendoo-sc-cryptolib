use algebra::PrimeField;
use primitives::{FieldBasedSignatureScheme, FieldBasedMerkleTreePath, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use crate::base_tx_circuit::base_tx_primitives::transaction::InputCoinBox;
use crate::transaction_box::zen_box::{InputZenBox, OutputZenBox};
use crate::TransactionProverData;

pub mod constraints;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct CoreTransaction<
    F: PrimeField,
    S: FieldBasedSignatureScheme<Data = F>,
    P: FieldBasedMerkleTreeParameters<Data = F>,
>
{
    pub inputs:                                     Vec<InputZenBox<F, S, P>>,
    pub outputs:                                    Vec<OutputZenBox<F, S, P>>,
    pub fee:                                        u64,
    pub custom_fields_hash:                         F,
    pub non_coin_boxes_input_ids_cumulative_hash:   F,
    pub non_coin_boxes_output_data_cumulative_hash: F,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CoreTransactionProverData<
    F: PrimeField,
    S: FieldBasedSignatureScheme<Data = F>,
    P: FieldBasedMerkleTreeParameters<Data = F>,
>
{
    pub core_tx:			CoreTransaction<F, S, P>, // Maybe move outside
    pub txs_tree_tx_path:   FieldBasedBinaryMHTPath<P>,
    pub prev_txs_tree_root: Option<F>,
    pub next_txs_tree_root: Option<F>,
    pub prev_mst_root:      Option<F>,
    pub next_mst_root:      Option<F>,
    pub prev_bvt_root:      Option<F>,
    pub next_bvt_root:      Option<F>,
    pub bvt_batch_size:		usize
}

impl<F: PrimeField, S: FieldBasedSignatureScheme<Data = F>, MHTP: FieldBasedMerkleTreePath> TransactionProverData
    for CoreTransactionProverData<F, S, MHTP> {}