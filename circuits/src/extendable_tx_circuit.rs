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
use std::marker::PhantomData;
use r1cs_std::eq::EqGadget;

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
        ];

        let end_states = vec![
            tx_g.get_next_txs_tree_root(),
            tx_g.get_next_mst_root(),
            tx_g.get_next_bvt_root(),
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
#[derive(Clone)]
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
    number_of_states:       usize,

    _hash:                  PhantomData<H>,
    _hash_gadget:           PhantomData<HG>,
    _sig_scheme:            PhantomData<S>,
    _sig_scheme_gadget:     PhantomData<SG>,
}

impl<ConstraintF, P, H, HG, S, SG> ExtendableTransactionCircuit<ConstraintF, P, H, HG, S, SG>
    where
        ConstraintF: Field,
        P:           FieldBasedMerkleTreeParameters<Data = ConstraintF, H = H>,
        H:           FieldBasedHash<Data = ConstraintF>,
        HG:          FieldBasedHashGadget<H, ConstraintF>,
        S:           FieldBasedSignatureScheme<Data = ConstraintF>,
        SG:          FieldBasedSigGadget<S, ConstraintF>,
{
    fn new(max_txs: usize, number_of_states: usize) -> Self {
        Self {
            core_txs: vec![],
            start_states: TransactionStates(vec![]),
            end_states: TransactionStates(vec![]),
            max_txs,
            number_of_states,
            _hash: PhantomData,
            _hash_gadget: PhantomData,
            _sig_scheme: PhantomData,
            _sig_scheme_gadget: PhantomData
        }
    }

    fn add_core_tx(&mut self, data: CoreTransactionProverData<ConstraintF, S, P>) {
        self.core_txs.push(data);
    }

    fn add_states(
        &mut self,
        start_states: TransactionStates<ConstraintF>,
        end_states: TransactionStates<ConstraintF>
    ) {
        assert_eq!(self.number_of_states, start_states.len());
        assert_eq!(self.number_of_states, end_states.len());
        self.start_states = start_states;
        self.end_states = end_states;
    }
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

        //let mut tx_states_gs = Vec::with_capacity(self.max_txs);
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

            //let core_tx_states_g = CoreTxStatesWrapper::<ConstraintF>::get_state_transitions_gadgets(&core_tx_g);
            //tx_states_gs.push(core_tx_states_g);

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

#[cfg(test)]
mod test {

    use super::*;
    use algebra::{
        fields::mnt4753::Fr,
        curves::mnt6753::G1Projective,
    };
    use primitives::{
        crh::poseidon::mnt4753::MNT4PoseidonHash as PoseidonHash,
        merkle_tree::{
            field_based_mht::mnt4753::MNT4753_MHT_POSEIDON_PARAMETERS as POSEIDON_TREE_PARAMETERS,
            FieldBasedMerkleTreePrecomputedEmptyConstants
        },
        signature::schnorr::field_based_schnorr::FieldBasedSchnorrSignatureScheme,
    };
    use r1cs_std::instantiated::mnt6_753::G1Gadget;
    use r1cs_crypto::{
        poseidon::mnt4753::MNT4PoseidonHashGadget as PoseidonHashGadget,
        signature::schnorr::field_based_schnorr::FieldBasedSchnorrSigVerificationGadget,
    };
    use proof_systems::groth16::{
        generator::generate_random_parameters, Parameters,
        prover::create_random_proof, Proof,
        verifier::{prepare_verifying_key, verify_proof}, PreparedVerifyingKey, VerifyingKey
    };
    use rand::{
        rngs::OsRng, Rng
    };

    struct TestMerkleTreeParameters {}

    impl FieldBasedMerkleTreeParameters for TestMerkleTreeParameters {
        type Data = Fr;
        type H = PoseidonHash;
        const MERKLE_ARITY: usize = 2;
        const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> = Some(POSEIDON_TREE_PARAMETERS);
    }

    type SchnorrSigScheme = FieldBasedSchnorrSignatureScheme<Fr, G1Projective, PoseidonHash>;
    type SchnorrVrfySigGadget = FieldBasedSchnorrSigVerificationGadget<
        Fr, G1Projective, G1Gadget, PoseidonHash, PoseidonHashGadget
    >;

    type TestCoreTxProverData = CoreTransactionProverData<Fr, SchnorrSigScheme, TestMerkleTreeParameters>;
    type TestExtendableTransactionCircuit = ExtendableTransactionCircuit<
        Fr,
        TestMerkleTreeParameters,
        PoseidonHash,
        PoseidonHashGadget,
        SchnorrSigScheme,
        SchnorrVrfySigGadget,
    >;

    #[test]
    fn simple_prove_verify_test()
    {
        let mut rng = OsRng::default();
        let max_txs = 16;
        let number_of_states = 4;

        // Generate proving and verifying key for our circuit. The data in the circuit can be None
        // (in case of single field elements), otherwise (like for Merkle Paths), must be some
        // collection of Field Elements of desired length (so the generator knows how many
        // witnesses/public inputs are allocated), but again they can be None (the generator doesn't
        // care about the actual value, but just how many they are). You can do this
        // by working with Default trait implementation of the structs in ExtendableTransactionCircuit,
        // if they are not good for this use case, you can provide new default implementation from
        // the main.
        let params = {
            let mut c = TestExtendableTransactionCircuit::new(16, 4);
            for _ in 0..16 {
                c.add_core_tx(TestCoreTxProverData::default());
            }
            let mut start_states = vec![Fr::default(); 4];
            let end_states = vec![Fr::default(); 4];
            c.add_states(start_states.clone(), end_states.clone);
            generate_random_parameters(c.clone(), &mut rng).unwrap()
        };

        // Create the proof, and now c must be populated with all the data (and concrete data)
        let proof = {
            let mut c = TestExtendableTransactionCircuit::new(16, 4);
            // Complete the circuit with actual data (or create a single circuit already with the actual
            // data and use it both for the generator and the prover).
            create_random_proof(c, &params, &mut rng).unwrap()
        };

        // Perform some precomputations on the verification key, in order to improve the
        // performances of the verifier algorithm
        let pvk = prepare_verifying_key(&params.vk);

        // Create the vector of public inputs for our circuit (in our case only the start_states
        // and end_states
        start_states.extend_from_slice(end_states.as_slice());

        // Verify the proof and assert that the proof verification is true.
        assert!(verify_proof(&pvk, &proof, start_states.as_slice()).unwrap());
    }
}