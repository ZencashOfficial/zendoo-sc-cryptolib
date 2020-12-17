use algebra::{PrimeField, Field};
use primitives::{FieldBasedSignatureScheme, FieldBasedMerkleTreeParameters, FieldBasedHash};
use crate::transaction::core_transaction::{CoreTransactionProverData, CoreTransaction};
use crate::{TransactionStates, Transaction, TransactionProverData};
use r1cs_core::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use r1cs_crypto::{FieldBasedHashGadget, FieldBasedSigGadget};
use crate::transaction::constraints::{TxStatesWrapper, TransactionTransitionsStatesGadget, TransactionGadget, TransactionStatesGadget};
use crate::transaction::core_transaction::constraints::CoreTransactionGadget;
use r1cs_std::fields::fp::FpGadget;
use r1cs_std::alloc::AllocGadget;
use r1cs_std::FromGadget;

pub struct CoreTxStatesWrapper<ConstraintF: Field> {}

impl<ConstraintF, P, H, HG, S, SG> TxStatesWrapper<
        ConstraintF,
        CoreTransaction<ConstraintF, S, P>,
        CoreTransactionProverData<ConstraintF, S, P>,
        P, H, HG, S, SG,
        CoreTransactionGadget<ConstraintF, P, H, HG, S, SG>
    >
for CoreTxStatesWrapper<ConstraintF> {
    fn get_state_transitions_gadgets(
        tx_g: &CoreTransactionGadget<ConstraintF, P, H, HG, S, SG>
    ) -> TransactionTransitionsStatesGadget<ConstraintF> {
        let start_states = vec![
            tx_g.get_prev_txs_tree_root(),
            tx_g.get_prev_mst_root(),
            tx_g.get_prev_bvt_root(),
            //phantom_cst_root_g, // To be defined
        ];

        let end_states = vec![
            tx_g.get_next_txs_tree_root(),
            tx_g.get_next_mst_root(),
            tx_g.get_next_bvt_root(),
            //phantom_cst_root_g, // To be defined
        ];
        return TransactionTransitionsStatesGadget::<ConstraintF>{
            start_states, end_states
        };
    }
}

//TODO: Templates are here actually only for CoinBox related stuff that each transaction
//      must share: this doesn't mean that each transaction can have its own signatures/
//      hashes/merkle trees. Since it's unlikely that we will change the CoinBox logic
//      it's the same if we remove the templates anyway, leading to more readable and
//      easy code (if we use type aliases like in ginger_calls.rs, even if we change
//      something, it will be easy to adapt, so we won't lose much generality anyway)
pub struct ExtendableTransactionCircuit<
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
>
{
    core_txs:               Vec<CoreTransactionProverData<ConstraintF, S, P>>,
    start_states:           TransactionStates<ConstraintF>,
    end_states:             TransactionStates<ConstraintF>,
    max_txs:                usize,

    _hash:                  PhantomData<H>,
    _hash_gadget:           PhantomData<HG>,
    _sig_scheme:            PhantomData<S>,
    _sig_scheme_gadget:     PhantomData<SG>,
}

impl<ConstraintF, P, H, HG, S, SG> ConstraintSynthesizer<ConstraintF> for ExtendableTransactionCircuit<ConstraintF, P, H, HG, S, SG>
where
    ConstraintF: Field,
    P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
    H:           FieldBasedHash<Data = ConstraintF>,
    HG:          FieldBasedHashGadget<H, ConstraintF>,
    S:           FieldBasedSignatureScheme<Data = ConstraintF>,
    SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(self, cs: &mut CS) -> Result<(), SynthesisError>
    {
        assert_eq!(self.max_txs, self.core_txs.len());

        let mut tx_states_gs = Vec::with_capacity(self.max_txs);
        let mut fee = FpGadget::<ConstraintF>::zero(cs.ns(|| "initialize fee"))?;

        let input_start_states = TransactionStatesGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc start states"),
            self.start_states
        )?;

        //Let’s assume fee is part of the start states and end states
        let mut cumulated_fee_g = input_start_states.0[0];

        let output_start_states = TransactionStatesGadget::<ConstraintF>::alloc_input(
            cs.ns(|| "alloc end states"),
            self.end_states
        )?;

        //Let’s assume fee is part of the start states and end states
        let final_cumulated_fee_g = output_start_states.0[0];

        // Core Tx part
        for (i, core_tx_data) in self.core_txs.iter().enumerate() {

            let core_tx_g = CoreTransactionGadget::<ConstraintF, P, H, HG, S, SG>::from(
                cs.ns(|| format!("alloc core_tx_{}", i)),
                core_tx_data.clone() // Can we avoid this ?
            )?;

            let is_phantom_tx = CoreTransactionGadget::<ConstraintF, P, H, HG, S, SG>::get_phantom().is_eq(
                cs.ns(|| format!("is phantom core_tx_{}", i)), core_tx_g
            )?;

            core_tx_g.conditionally_enforce(
                cs.ns(|| format!("enforce rules for core_tx_{}", i)),
                is_phantom_tx.not()
            )?;

            let core_tx_states_g = CoreTxStatesWrapper::<ConstraintF>::get_state_transitions_gadgets(&core_tx_g);
            tx_states_gs.push(core_tx_states_g);

            let tx_fee_g = core_tx_g.get_fee();
            cumulated_fee_g.conditionally_add(
                cs.ns(|| format!("conditionally add fee for core_tx_{}", i)),
                &tx_fee_g,
                &is_phantom_tx.not()
            )?;
        }


        /*//Enforce order
        let ordering_g = OrderingTransactionGadget::new(tx_states_gs);
        ordering_g.enforce_order(
            cs.ns(...),input_start_states[1..],output_start_states[1..]
        )?;*/

        //Enforce fee
        cumulated_fee_g.enforce_equal(cs.ns(|| "enforce correct cumulated fee"), final_cumulated_fee_g)?;

        Ok(())

    }
}