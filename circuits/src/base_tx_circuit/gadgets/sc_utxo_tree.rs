use algebra::fields::PrimeField;
use primitives::merkle_tree::field_based_mht::FieldBasedMerkleTreeParameters;
use r1cs_crypto::{
    crh::FieldBasedHashGadget,
    merkle_tree::field_based_mht::FieldBasedBinaryMerkleTreePathGadget,
};
use r1cs_std::{
    alloc::ConstantGadget,
    bits::boolean::Boolean,
    fields::fp::FpGadget,
};
use r1cs_core::{
    ConstraintSystem, SynthesisError
};
use crate::base_tx_circuit::gadgets::transition::MerkleTreeTransitionGadget;
use std::marker::PhantomData;

pub struct SCUtxoTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    _tree_params: PhantomData<P>,
    _hash_gadget: PhantomData<HGadget>,
    _field:       PhantomData<ConstraintF>,
}

impl<P, HGadget, ConstraintF> SCUtxoTreeGadget<P, HGadget, ConstraintF>
    where
        P: FieldBasedMerkleTreeParameters<Data = ConstraintF>,
        HGadget: FieldBasedHashGadget<P::H, ConstraintF, DataGadget = FpGadget<ConstraintF>>,
        ConstraintF: PrimeField,
{
    /// If `should_enforce` is True, enforces removal of `start_leaf` located at `start_path`,
    /// and insertion of `new_dest_leaf` located at `dest_path`, in a Merkle Tree with root
    /// `start_root`, returning the root of the new Merkle Tree; otherwise does nothing and
    /// returns the old root `start_root`.
    pub fn conditionally_enforce_state_transition<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        start_root: &HGadget::DataGadget,
        start_path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        start_leaf: &HGadget::DataGadget,
        dest_path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        new_dest_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::conditionally_enforce_state_transition(
            cs, start_root, start_path, start_leaf, &null_leaf,
            dest_path, &null_leaf, new_dest_leaf, should_enforce,
        )
    }

    /// If `should_enforce` is True enforces removal of `leaf` located at `path` from a Merkle Tree
    /// rooted at `root`, and returns the root of the new tree, otherwise does nothing and returns
    /// the old root `root`.
    pub fn conditionally_enforce_leaf_removal<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        root: &HGadget::DataGadget,
        path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::conditionally_enforce_leaf_replacement(
            cs, root, path, leaf, &null_leaf, should_enforce,
        )
    }

    /// if `should_enforce` is True enforces the insertion in a Merkle Tree rooted at `root` of
    /// `new_leaf` located at `path`, and returns the root of the new tree, otherwise does nothing
    /// and returns the old root `root`.
    pub fn conditionally_enforce_leaf_insertion<CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        root: &HGadget::DataGadget,
        path: &FieldBasedBinaryMerkleTreePathGadget<P, HGadget, ConstraintF>,
        new_leaf: &HGadget::DataGadget,
        should_enforce: &Boolean,
    ) -> Result<HGadget::DataGadget, SynthesisError>
    {
        let null_leaf = ConstantGadget::<ConstraintF, ConstraintF>::from_value(
            cs.ns(|| "hardcode null leaf"),
            &P::EMPTY_HASH_CST.unwrap().nodes[0]
        );

        MerkleTreeTransitionGadget::<P, HGadget, ConstraintF>::conditionally_enforce_leaf_replacement(
            cs, root, path, &null_leaf, new_leaf, should_enforce,
        )
    }
}

#[cfg(test)]
mod test {

    use algebra::{
        fields::mnt4753::Fr, bits::ToBits, UniformRand,
    };
    use primitives::{field_based_mht::{
        BigMerkleTree, FieldBasedMerkleTreeParameters,
        FieldBasedMerkleTreePrecomputedEmptyConstants,
        mnt4753::MNT4753_MHT_POSEIDON_PARAMETERS,
        smt::Coord,
    }, crh::poseidon::mnt4753::MNT4PoseidonHash};
    use rand::{
        rngs::OsRng, Rng
    };
    use r1cs_std::{
        fields::{
            fp::FpGadget, FieldGadget,
        },
        alloc::AllocGadget,
        bits::boolean::Boolean,
        test_constraint_system::TestConstraintSystem
    };
    use r1cs_crypto::{
        field_based_mht::FieldBasedMerkleTreePathGadget,
        crh::mnt4753::MNT4PoseidonHashGadget,
    };
    use r1cs_core::ConstraintSystem;
    use super::SCUtxoTreeGadget;

    #[derive(Debug, Clone)]
    struct TestMerkleTreeParameters;

    impl FieldBasedMerkleTreeParameters for TestMerkleTreeParameters {
        type Data = Fr;
        type H = MNT4PoseidonHash;
        const MERKLE_ARITY: usize = 2;
        const EMPTY_HASH_CST: Option<FieldBasedMerkleTreePrecomputedEmptyConstants<'static, Self::H>> =
            Some(MNT4753_MHT_POSEIDON_PARAMETERS);
    }

    type TestSMT = BigMerkleTree<TestMerkleTreeParameters>;
    type TestSMTGadget = SCUtxoTreeGadget<TestMerkleTreeParameters, MNT4PoseidonHashGadget, Fr>;

    type TestSMTPathGadget = FieldBasedMerkleTreePathGadget<TestMerkleTreeParameters, MNT4PoseidonHashGadget, Fr>;

    fn leaf_to_index(leaf: &Fr, height: usize) -> usize {

        // Convert field element to bits
        let bits = leaf.write_bits();
        assert!(height <= bits.len());

        // Use log_2(num_leaves) MSB of serialized FieldElement to estabilish leaf position inside
        // the tree
        let leaf_bits = &bits[..height];
        let position = leaf_bits.iter().rev().fold(0, |acc, &b| acc*2 + b as usize);
        position
    }

    // Get random SMT of height `height` initialized with `leaves_num` random leaves.
    fn initialize_random_tree<R: Rng>(height: usize, leaves_num: usize, rng: &mut R, path: &str) -> (TestSMT, Vec<Fr>) {
        let mut leaves = vec![];

        // Get tree
        let mut smt = TestSMT::new(
            height,
            false,
            path.to_owned(),
        ).unwrap();

        // Initialize tree by adding leaves_num leaves in different positions
        for _ in 0..leaves_num {
            loop {
                let r = Fr::rand(rng);
                let position = leaf_to_index(&r, height);
                if smt.is_leaf_empty(Coord::new(0, position))
                { //Ensure that each leaf ends up in a different position
                    leaves.push(r);
                    smt.insert_leaf(Coord::new(0, position), r);
                    break;
                }
            }
        }

        (smt, leaves)
    }

    #[test]
    fn test_random_transitions() {
        let mut rng = OsRng;
        let height = 6;

        // Get random tree
        let (mut smt, leaves) = initialize_random_tree(
            height,
            32,
            &mut rng,
            "test_random_transitions"
        );

        let mut cs = TestConstraintSystem::<Fr>::new();

        leaves.into_iter().enumerate().for_each(|(i, leaf)| {

            let start_position = leaf_to_index(&leaf, height);

            // Get root before leaf removal
            let primitive_start_root = smt.get_root();

            // Get start leaf path
            let primitive_start_path = smt.get_merkle_path(Coord::new(0, start_position));

            // Remove leaf
            smt.remove_leaf(Coord::new(0, start_position));

            // Get root after leaf removal
            let primitive_interim_root = smt.get_root();

            // Alloc removed leaf
            let start_leaf = FpGadget::<Fr>::alloc(
                cs.ns(|| format!("alloc start_leaf_{}", i)),
                || Ok(leaf)
            ).unwrap();

            // Alloc start root
            let start_root = FpGadget::<Fr>::alloc(
                cs.ns(|| format!("alloc start_root_{}", i)),
                || Ok(primitive_start_root)
            ).unwrap();

            // Alloc start path
            let start_path = TestSMTPathGadget::alloc(
                cs.ns(|| format!("alloc start_path_{}", i)),
                || Ok(primitive_start_path)
            ).unwrap();

            // Enforce leaf removal
            let interim_root = TestSMTGadget::conditionally_enforce_leaf_removal(
                cs.ns(|| format!("enforce leaf removal {}", i)),
                &start_root,
                &start_path,
                &start_leaf,
                &Boolean::constant(true)
            ).unwrap();

            assert_eq!(primitive_interim_root, interim_root.get_value().unwrap());

            // Insert new random leaf in an empty position
            let (primitive_dest_leaf, dest_position) = loop {
                let r = Fr::rand(&mut rng);
                let position = leaf_to_index(&r, height);
                if smt.is_leaf_empty(Coord::new(0, position))
                {
                    smt.insert_leaf(Coord::new(0, position), r);
                    break (r, position);
                }
            };

            // Get root after leaf insertion
            let primitive_dest_root = smt.get_root();

            // Get dest leaf path
            let primitive_dest_path = smt.get_merkle_path(Coord::new(0, dest_position));

            // Alloc inserted leaf
            let dest_leaf = FpGadget::<Fr>::alloc(
                cs.ns(|| format!("alloc dest_leaf_{}", i)),
                || Ok(primitive_dest_leaf)
            ).unwrap();

            // Alloc dest path
            let dest_path = TestSMTPathGadget::alloc(
                cs.ns(|| format!("alloc dest_path_{}", i)),
                || Ok(primitive_dest_path)
            ).unwrap();

            // Enforce leaf insertion
            let dest_root = TestSMTGadget::conditionally_enforce_leaf_insertion(
                cs.ns(|| format!("enforce leaf insertion {}", i)),
                &interim_root,
                &dest_path,
                &dest_leaf,
                &Boolean::constant(true)
            ).unwrap();

            assert_eq!(primitive_dest_root, dest_root.get_value().unwrap());

            // Using enforce_state_transition is the same
            let dest_root_1 = TestSMTGadget::conditionally_enforce_state_transition(
                cs.ns(|| format!("enforce state transition {}", i)),
                &start_root,
                &start_path,
                &start_leaf,
                &dest_path,
                &dest_leaf,
                &Boolean::constant(true)
            ).unwrap();

            assert_eq!(primitive_dest_root, dest_root_1.get_value().unwrap());
        });

        if !cs.is_satisfied() {
            println!("**************Unsatisfied constraints: {:?}**************", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }
}