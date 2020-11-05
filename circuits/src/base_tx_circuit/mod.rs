pub mod gadgets;
pub mod base_tx_primitives;
pub mod constants;

use algebra::{PrimeField, ProjectiveCurve, ToConstraintField};
use primitives::{FieldBasedHash, FieldBasedMerkleTreeParameters, FieldBasedBinaryMHTPath};
use r1cs_std::{
    groups::GroupGadget, to_field_gadget_vec::ToConstraintFieldGadget,
    fields::fp::FpGadget,
};
use r1cs_crypto::FieldBasedHashGadget;
use crate::base_tx_circuit::{
    base_tx_primitives::transaction::BaseTransaction,
    constants::BaseTransactionParameters
};
use std::marker::PhantomData;

/// Base proof of transition for a single payment transaction, able to contain more than on
/// input/output coin box. The approach is to sequentially enforce one input/output transition
/// at time in the transaction.
pub struct BaseTransactionCircuit<
    ConstraintF: PrimeField,
    G: ProjectiveCurve + ToConstraintField<ConstraintF>,
    GG: GroupGadget<G, ConstraintF, Value = G> + ToConstraintFieldGadget<ConstraintF, FieldGadget = FpGadget<ConstraintF>>,
    H: FieldBasedHash<Data = ConstraintF>,
    HG: FieldBasedHashGadget<H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
    TXP: BaseTransactionParameters<ConstraintF, G>,
    MHTP: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
>
{
    /////////////////////////// Witnesses

    /// A transaction with `MAX_I_O_BOXES` coin box inputs and `MAX_I_O_BOXES` coin box outputs
    tx_pay:                   Option<BaseTransaction<ConstraintF, G, H, TXP>>,

    /// Merkle Paths to the leaf where `tx_pay` will be placed in the Applied Payment Transactions Merkle Tree
    txs_tree_tx_path:         Option<FieldBasedBinaryMHTPath<MHTP>>,

    /// Merkle Paths to the leaves where the inputs are placed in the Merkle State Tree
    mst_paths_to_inputs:      Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Merkle Paths to the leaves where the outputs are placed in the Merkle State Tree
    mst_paths_to_outputs:     Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Merkle Paths to the leaves where the inputs are placed in the Bit Vector Tree
    bvt_paths_to_inputs:      Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Leaves corresponding to the Merkle paths in `bvt_paths_to_inputs`
    prev_bvt_input_leaves:    Vec<Option<MHTP::Data>>,

    /// Merkle Paths to the leaves where the outputs are placed in the Merkle State Tree
    bvt_paths_to_outputs:     Vec<Option<FieldBasedBinaryMHTPath<MHTP>>>,

    /// Leaves corresponding to the Merkle paths in `bvt_paths_to_outputs`
    prev_bvt_output_leaves:   Vec<Option<MHTP::Data>>,

    /////////////////////////// Public inputs

    /// Merkle State Tree Root before applying `tx_pay`
    scb_prev_mst_root:        Option<MHTP::Data>,

    /// Merkle State Tree Root after applying `tx_pay`
    scb_new_mst_root:         Option<MHTP::Data>,

    /// Applied Payment Transactions Merkle Tree Root before applying `tx_pay`
    scb_prev_txs_tree_root:   Option<MHTP::Data>,

    /// Applied Payment Transactions Merkle Tree Root after applying `tx_pay`
    scb_new_txs_tree_root:    Option<MHTP::Data>,

    /// Fee associated to `tx_pay` explicitly needed as public input to bring it
    /// up recursively in the proof tree, since it will be used in the block proof
    /// to enforce the forger's payment
    scb_fee:                  Option<FpGadget<ConstraintF>>,

    /// Bit Vector Tree Root before applying `tx_pay`
    scb_prev_bvt_root:        Option<MHTP::Data>,

    /// Bit Vector Tree Root after applying `tx_pay`
    scb_next_bvt_root:        Option<MHTP::Data>,

    /////////////////////////// Others

    _group_gadget:            PhantomData<GG>,
    _hash_gadget:             PhantomData<HG>,
}