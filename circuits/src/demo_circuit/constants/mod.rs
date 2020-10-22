use algebra::{
    fields::mnt4753::Fr,
    curves::mnt6753::G1Projective,
    biginteger::BigInteger768 as BigInteger,
    Field, PrimeField, ProjectiveCurve,
};

use primitives::{
    crh::pedersen::PedersenWindow,
    signature::schnorr::field_based_schnorr::{
        FieldBasedSchnorrSignature, FieldBasedSchnorrPk,
    }
};

pub mod constants;

pub struct NaiveThresholdSigParams{
    pub null_sig:   FieldBasedSchnorrSignature<Fr, G1Projective>,
    pub null_pk:    FieldBasedSchnorrPk<G1Projective>,
}

impl NaiveThresholdSigParams {
    pub fn new() -> Self {
        let e = Fr::one();
        let s = e.clone();
        let null_sig = FieldBasedSchnorrSignature::<Fr, G1Projective>::new(e, s);

        let x = Fr::from_repr(
            BigInteger([
                17938625038075785283,
                16508371799393812784,
                15483496128959353847,
                2048968449075429543,
                16732582715505535218,
                17185233299328629254,
                215284426071672551,
                5549254975250138323,
                1580560065762820894,
                7090381661442181239,
                14966187896916716816,
                75867572971213,
            ]));

        let y = Fr::from_repr(
            BigInteger([
                10704811943041274771,
                2767103289650614019,
                14558604087270339633,
                16118780849751543899,
                8585597437853085838,
                449342974578382641,
                8088465320681580870,
                509643884085664102,
                15310217451837794004,
                4730806010349112824,
                13668444198414977264,
                219272068411579,
            ]));

        let z = Fr::from_repr(
            BigInteger([
                13373016969058414402,
                5670427856875409064,
                11667651089292452217,
                1113053963617943770,
                12325313033510771412,
                11510260603202358114,
                3606323059104122008,
                6452324570546309730,
                4644558993695221281,
                1127165286758606988,
                10756108507984535957,
                135547536859714,
            ]));

        let null_pk = FieldBasedSchnorrPk(G1Projective::new(x, y, z));

        Self{null_sig, null_pk}
    }
}

#[derive(Clone)]
pub struct VRFWindow {}
impl PedersenWindow for VRFWindow {
    const WINDOW_SIZE: usize = 128;
    const NUM_WINDOWS: usize = 2;
}

pub struct VRFParams{
    pub group_hash_generators: Vec<Vec<G1Projective>>,
}

impl VRFParams {
    pub fn new() -> Self {

        let gen_1 = G1Projective::new(
        Fr::from_repr(
            BigInteger([
                1294449187585434704,
                5131287438243136725,
                18081355146140789575,
                15814805185239782286,
                4405965803081461763,
                4617523924423324244,
                8379615642753764988,
                2000790817957976954,
                1770743024696829222,
                664039781157959360,
                8894836393413418304,
                108509189311559,
            ])),
        Fr::from_repr(
            BigInteger([
                14207092875898659328,
                17205966376070017323,
                17535583566531148253,
                16415296113678429706,
                15093927965206654338,
                7770144268668767567,
                929832473226976009,
                10710907410150181098,
                13777945618797139330,
                5683769430746598257,
                1088380296753030517,
                324687205438666,
            ])),
        Fr::from_repr(
            BigInteger([
                13373016969058414402,
                5670427856875409064,
                11667651089292452217,
                1113053963617943770,
                12325313033510771412,
                11510260603202358114,
                3606323059104122008,
                6452324570546309730,
                4644558993695221281,
                1127165286758606988,
                10756108507984535957,
                135547536859714,
            ])),
        );

        let gen_2 = G1Projective::new(
        Fr::from_repr(
            BigInteger([
                649859634879180958,
                13597720379005621868,
                18064174816613973740,
                8646429382307887638,
                17014556852349184586,
                1341584681953572340,
                10416830578026787120,
                12570924511801367504,
                3370224175163505491,
                16453203747482544835,
                16824394801845877290,
                57717353992973,
            ])),
        Fr::from_repr(
            BigInteger([
                11571775449869477883,
                5057296380047860478,
                8041855877286195997,
                32169344314064857,
                3655001595782824013,
                3080788830673849929,
                7716699506620825739,
                16062320569088622625,
                205603018711731380,
                17023118407673105708,
                4011605409044447956,
                324662289883754,
            ])),
        Fr::from_repr(
            BigInteger([
                13373016969058414402,
                5670427856875409064,
                11667651089292452217,
                1113053963617943770,
                12325313033510771412,
                11510260603202358114,
                3606323059104122008,
                6452324570546309730,
                4644558993695221281,
                1127165286758606988,
                10756108507984535957,
                135547536859714,
            ])),
        );

        let group_hash_generators = Self::compute_group_hash_table([gen_1, gen_2].to_vec());

        Self{group_hash_generators}
    }

    pub(crate) fn compute_group_hash_table(generators: Vec<G1Projective>)
    -> Vec<Vec<G1Projective>>
    {
        let mut gen_table = Vec::new();
        for i in 0..VRFWindow::NUM_WINDOWS {
            let mut generators_for_segment = Vec::new();
            let mut base = generators[i];
            for _ in 0..VRFWindow::WINDOW_SIZE {
                generators_for_segment.push(base);
                for _ in 0..4 {
                    base.double_in_place();
                }
            }
            gen_table.push(generators_for_segment);
        }
        gen_table
    }
}

#[cfg(test)]
mod test
{
    use algebra::{curves::mnt6753::G1Affine, FpParameters, FromCompressedBits, AffineCurve};
    use super::*;
    use blake2s_simd::{
        Hash, Params
    };
    use bit_vec::BitVec;

    fn hash_to_curve<F: PrimeField, G: AffineCurve + FromCompressedBits>(
        tag: &[u8],
        personalization: &[u8]
    ) -> Option<G> {

        let compute_chunk =
            |input: &[u8], personalization: &[u8]| -> Hash {
                Params::new()
                    .hash_length(32)
                    .personal(personalization)
                    .to_state()
                    .update(constants::GH_FIRST_BLOCK)
                    .update(input)
                    .finalize()
            };

        // Append counter byte to tag
        let tag_len = tag.len();
        let mut tag = tag.to_vec();
        tag.push(0u8);

        // Compute number of hashes to be concatenated in order to obtain a field element
        let field_size = F::size_in_bits();
        let bigint_size = (field_size + F::Params::REPR_SHAVE_BITS as usize)/8;
        let chunk_num = if bigint_size % 32 == 0 { bigint_size/32 } else { (bigint_size/32) + 1};
        let max_value = u8::max_value();
        let mut g = None;

        while tag[tag_len] <= max_value {

            let mut chunks = vec![];

            //chunk_0 = H(tag), chunk_1 = H(chunk_0) = H(H(tag)), ..., chunk_i = H(chunk_i-1)
            let mut prev_hash = tag.clone();
            for _ in 0..chunk_num {
                let hash = compute_chunk(prev_hash.as_slice(), personalization);
                chunks.extend_from_slice(hash.as_ref());
                prev_hash = hash.as_ref().to_vec();
            }

            tag[tag_len] += 1u8;

            //Mask away REPR_SHAVE_BITS
            let mut chunk_bits = BitVec::from_bytes(chunks.as_slice());
            for i in field_size..(bigint_size * 8) {
                chunk_bits.set(i, false);
            }

            //Get field element from `chunks`
            let chunk_bytes = chunk_bits.to_bytes();
            let fe = match F::from_random_bytes(&chunk_bytes[..bigint_size]) {
                Some(fe) => fe,
                None => continue
            };

            //Get point from chunks
            let mut fe_bits = fe.write_bits();
            fe_bits.push(false); //We don't want an infinity point
            fe_bits.push(false); //We decide to choose the even y coordinate
            match G::decompress(fe_bits) {
                Ok(point) => {
                    g = Some(point);
                    break;
                },
                Err(_) => continue
            };
        };
        g
    }


    #[test]
    fn test_pk_null_gen() {
        let tag = b"Strontium Sr 90";
        let personalization = constants::NULL_PK_PERSONALIZATION;
        let htc_out = hash_to_curve::<Fr, G1Affine>(tag, personalization)
            .unwrap()
            .into_projective();
        println!("{:#?}", htc_out);
        let null_pk = NaiveThresholdSigParams::new().null_pk.0;
        assert_eq!(htc_out, null_pk);
    }

    #[test]
    fn test_vrf_group_hash_gen() {
        let personalization = constants::VRF_GROUP_HASH_GENERATORS_PERSONALIZATION;

        //Gen1
        let tag = b"Magnesium Mg 12";
        let htc_g1_out = hash_to_curve::<Fr, G1Affine>(tag, personalization)
            .unwrap()
            .into_projective();
        println!("{:#?}", htc_g1_out);

        //Gen2
        let tag = b"Gold Au 79";
        let htc_g2_out = hash_to_curve::<Fr, G1Affine>(tag, personalization)
            .unwrap()
            .into_projective();
        println!("{:#?}", htc_g2_out);

        //Check GH generators
        let gh_generators = VRFParams::compute_group_hash_table(
            [htc_g1_out, htc_g2_out].to_vec()
        );
        assert_eq!(gh_generators, VRFParams::new().group_hash_generators);
    }
}