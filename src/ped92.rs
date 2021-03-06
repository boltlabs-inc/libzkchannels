// ped92.rs
use ff::{Field, PrimeField, Rand};
use pairing::{CurveProjective, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt;
use util;
use util::is_vec_g1_equal;

#[derive(Clone)]
pub struct CSParams<E: Engine> {
    pub g: E::G1,
    pub h: E::G1,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as pairing::Engine>::G1: serde::Serialize"))]
#[serde(bound(deserialize = "<E as pairing::Engine>::G1: serde::Deserialize<'de>"))]
pub struct Commitment<E: Engine> {
    pub c: E::G1,
}

impl<E: Engine> PartialEq for Commitment<E> {
    fn eq(&self, other: &Commitment<E>) -> bool {
        self.c == other.c
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as pairing::Engine>::G1: serde::Serialize"))]
#[serde(bound(deserialize = "<E as pairing::Engine>::G1: serde::Deserialize<'de>"))]
pub struct CSMultiParams<E: Engine> {
    pub pub_bases: Vec<E::G1>,
}

impl<E: Engine> PartialEq for CSMultiParams<E> {
    fn eq(&self, other: &CSMultiParams<E>) -> bool {
        is_vec_g1_equal::<E>(&self.pub_bases, &other.pub_bases)
    }
}

impl<E: Engine> CSMultiParams<E> {
    pub fn from_slice<'de>(ser_gs: &'de [u8], g_len: usize, num_elems: usize) -> Self
    where
        <E as pairing::Engine>::G1: serde::Deserialize<'de>,
    {
        let mut pub_bases: Vec<E::G1> = Vec::new();
        let mut start_pos = 0;
        let mut end_pos = g_len;
        for _ in 0..num_elems {
            let g: E::G1 = serde_json::from_slice(&ser_gs[start_pos..end_pos]).unwrap();
            start_pos = end_pos;
            end_pos += g_len;
            pub_bases.push(g);
        }

        return CSMultiParams { pub_bases };
    }
}

impl<E: Engine> fmt::Display for CSMultiParams<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut y_str = String::new();
        let mut i = 0;
        for y in self.pub_bases.iter() {
            y_str = format!("{}\n{} => {}", y_str, i, y);
            i += 1;
        }

        write!(f, "CSMultiParams : (\n{}\n)", y_str)
    }
}

impl<E: Engine> fmt::Display for Commitment<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Commitment : (c={})", &self.c)
    }
}

impl<E: Engine> CSParams<E> {
    /*
    Implements the setup algorithm for the Pedersen92 commitment scheme
    */
    pub fn setup<R: Rng>(rng: &mut R) -> Self {
        let g = E::G1::rand(rng);
        let h = E::G1::rand(rng);
        CSParams { g, h }
    }

    /*
    commit(pk, msg) -> cm where
    - pk is the public key generated from setup()
    - msg is the message structure for the commitment scheme
    - cm is the output commitment message for the given message
    */
    pub fn commit<R: Rng>(&self, rng: &mut R, m: E::Fr, R: Option<E::Fr>) -> Commitment<E> {
        let r = R.unwrap_or(E::Fr::rand(rng));

        // c = g^m * h^r
        let mut c = self.g.clone();
        c.mul_assign(m.clone());
        let mut h = self.h.clone();
        h.mul_assign(r.clone());
        c.add_assign(&h);

        Commitment { c }
    }

    /*
    decommit(csp, cm, msg) -> bool where
    - cm is the commitment
    - m is the message to validate
    - outputs T/F for whether the cm is a valid commitment to the msg
    */
    pub fn decommit(&self, cm: &Commitment<E>, m: &E::Fr, r: &E::Fr) -> bool {
        let mut dm = self.g.clone();
        dm.mul_assign(m.clone());
        let mut h = self.h.clone();
        h.mul_assign(r.clone());
        dm.add_assign(&h);
        dm == cm.c
    }
}

impl<E: Engine> CSMultiParams<E> {
    /*
    Implements the setup algorithm for the Pedersen92 commitment scheme over
    a vector of messages of length len.
    */
    pub fn setup_gen_params<R: Rng>(rng: &mut R, len: usize) -> Self {
        let mut p: Vec<E::G1> = Vec::new();
        // 1 extra base element for the random parameter
        for _i in 0..len + 1 {
            p.push(E::G1::rand(rng));
        }
        CSMultiParams { pub_bases: p }
    }

    pub fn commit(&self, x: &Vec<E::Fr>, r: &E::Fr) -> Commitment<E> {
        // c = g1^m1 * ... * gn^mn * h^r
        let mut c = self.pub_bases[0].clone();
        let p_len = self.pub_bases.len();
        c.mul_assign(r.clone());
        //println!("commit => x.len = {}, p.len = {}", x.len(), p_len);
        for i in 0..x.len() {
            if (i < p_len) {
                let mut basis = self.pub_bases[i + 1];
                basis.mul_assign(x[i]);
                c.add_assign(&basis);
            }
        }
        Commitment { c }
    }

    pub fn extend_commit(&self, com: &Commitment<E>, x: &E::Fr) -> Commitment<E> {
        // c = com * gn+1 ^ x
        let len = self.pub_bases.len();
        let mut c = self.pub_bases[len - 1].clone();
        c.mul_assign(x.clone());
        c.add_assign(&com.c);

        return Commitment { c };
    }

    pub fn remove_commit(&self, com: &Commitment<E>, x: &E::Fr) -> Commitment<E> {
        // c = com * gn+1 ^ x
        let len = self.pub_bases.len();
        let mut c = self.pub_bases[len - 1].clone();
        let xx = x.clone();
        c.mul_assign(xx);
        c.negate();
        c.add_assign(&com.c);

        return Commitment { c };
    }

    pub fn decommit(&self, cm: &Commitment<E>, x: &Vec<E::Fr>, r: &E::Fr) -> bool {
        let l = x.len();
        // pub_base[0] => h, x[0] => r
        let mut dc = self.pub_bases[0].clone();
        dc.mul_assign(r.clone());
        for i in 0..l {
            let mut basis = self.pub_bases[i + 1];
            basis.mul_assign(x[i]);
            dc.add_assign(&basis);
        }
        return dc == cm.c;
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct CommitmentProof<E: Engine> {
    pub T: E::G1,
    pub z: Vec<E::Fr>,
}

impl<E: Engine> CommitmentProof<E> {
    pub fn new<R: Rng>(
        csprng: &mut R,
        com_params: &CSMultiParams<E>,
        com: &E::G1,
        message: &Vec<E::Fr>,
        r: &E::Fr,
        reveal_index: &Vec<usize>,
    ) -> Self {
        let mut rt = Vec::new();
        for i in 0..message.len() + 1 {
            if reveal_index.contains(&i) {
                rt.push(E::Fr::zero());
            } else {
                rt.push(E::Fr::rand(csprng));
            }
        }

        let (Tvals, t) =
            CommitmentProof::<E>::prove_commitment::<R>(csprng, com_params, message, Some(rt));

        // compute the challenge
        let x: Vec<E::G1> = vec![Tvals, com.clone()];
        let challenge = util::hash_g1_to_fr::<E>(&x);

        // compute the response
        CommitmentProof::<E>::prove_response(message, r, Tvals, &t, &challenge)
    }

    pub fn prove_commitment<R: Rng>(
        csprng: &mut R,
        com_params: &CSMultiParams<E>,
        message: &Vec<E::Fr>,
        tOptional: Option<Vec<E::Fr>>,
    ) -> (E::G1, Vec<E::Fr>) {
        let mut Tvals = E::G1::zero();
        assert!(message.len() <= com_params.pub_bases.len());
        let mut t = tOptional.unwrap_or(Vec::<E::Fr>::with_capacity(message.len() + 1));
        // aspects of wallet being revealed
        for i in 0..message.len() + 1 {
            if t.len() == i {
                t.push(E::Fr::rand(csprng));
            }
            let ti = t[i].clone();
            let mut gt = com_params.pub_bases[i].clone();
            gt.mul_assign(ti.into_repr());
            Tvals.add_assign(&gt);
        }
        (Tvals, t)
    }

    pub fn prove_response(
        message: &Vec<E::Fr>,
        r: &E::Fr,
        Tvals: E::G1,
        t: &Vec<E::Fr>,
        challenge: &E::Fr,
    ) -> CommitmentProof<E> {
        let mut z: Vec<E::Fr> = Vec::new();
        let mut z0 = r.clone();
        z0.mul_assign(&challenge);
        z0.add_assign(&t[0]);
        z.push(z0);
        for i in 1..t.len() {
            let mut zi = message[i - 1].clone();
            zi.mul_assign(&challenge);
            zi.add_assign(&t[i]);
            z.push(zi);
        }

        CommitmentProof {
            T: Tvals, // commitment challenge
            z: z,     // response values
        }
    }

    pub fn verify_proof(
        &self,
        com_params: &CSMultiParams<E>,
        com: &<E as Engine>::G1,
        challenge: &E::Fr,
        revealOption: Option<Vec<Option<E::Fr>>>,
    ) -> bool {
        let mut comc = com.clone();
        let T = self.T.clone();
        comc.mul_assign(challenge.into_repr());
        comc.add_assign(&T);
        let mut x = E::G1::zero();
        let reveal = revealOption.unwrap_or(vec![]);
        let mut revealBool = true;
        for i in 0..self.z.len() {
            let mut base = com_params.pub_bases[i].clone();
            base.mul_assign(self.z[i].into_repr());
            x.add_assign(&base);

            if reveal.len() > i && reveal[i].is_some() {
                let mut el = reveal[i].unwrap();
                el.mul_assign(&challenge.clone());
                revealBool = revealBool && self.z[i] == el;
            }
        }
        revealBool && comc == x
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use pairing::bls12_381::{Bls12, Fr, G1};
    use rand::thread_rng;
    use wallet::Wallet;

    #[test]
    fn commit_one_message_works() {
        let rng = &mut thread_rng();
        let csp = CSParams::<Bls12>::setup(rng);

        let m1 = Fr::rand(rng);
        let mut m2 = m1.clone();
        m2.add_assign(&Fr::one());
        let r = Fr::rand(rng);
        let c = csp.commit(rng, m1, Some(r));

        assert_eq!(csp.decommit(&c, &m1, &r), true);
        assert_eq!(csp.decommit(&c, &m2, &r), false);
    }

    #[test]
    fn commit_n_message_works() {
        let rng = &mut thread_rng();
        let len = 3;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let mut m: Vec<Fr> = Vec::new();
        for _i in 0..len {
            m.push(Fr::rand(rng));
        }
        let r = Fr::rand(rng);
        let c = csp.commit(&m, &r);

        assert_eq!(csp.decommit(&c, &m, &r), true);
        let mut r1 = r.clone();
        r1.add_assign(&Fr::one());
        assert_eq!(csp.decommit(&c, &m, &r1), false);
    }

    #[test]
    fn commit_variable_messages_works() {
        let rng = &mut thread_rng();
        let len = 5;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let mut m1: Vec<Fr> = Vec::new();
        for _i in 0..len - 1 {
            m1.push(Fr::rand(rng));
        }
        let extra_m = Fr::rand(rng);
        let r = Fr::rand(rng);

        let c1 = csp.commit(&m1, &r);

        assert_eq!(csp.decommit(&c1, &m1, &r), true);
        let mut r1 = r.clone();
        r1.add_assign(&Fr::one());
        assert_eq!(csp.decommit(&c1, &m1, &r1), false);

        // let's add another message
        let mut m2 = m1.clone();
        m2.push(extra_m);
        let c2 = csp.commit(&m2, &r);
        assert_eq!(csp.decommit(&c2, &m2, &r), true);
    }

    #[test]
    fn test_csp_basic_serialize() {
        let rng = &mut rand::thread_rng();
        let len = 5;
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, len);

        let serialized = serde_json::to_string(&csp).unwrap();

        let _csp_des: CSMultiParams<Bls12> = serde_json::from_str(&serialized).unwrap();
    }

    #[test]
    fn test_proof_commitment() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let rho = Fr::rand(rng);
        let tau = Fr::rand(rng);
        let tau_bar = Fr::rand(rng);

        let bc = rng.gen_range(100, 1000);
        let bm = rng.gen_range(100, 1000);
        let wallet = Wallet::<Bls12> {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc: bc,
            bm: bm,
        };

        let comParams = CSMultiParams::setup_gen_params(rng, 5);
        let rl_com = comParams.commit(&vec![wallet.rev_lock], &rho);
        let s_com = comParams.commit(&wallet.as_fr_vec().clone(), &tau);
        let s_bar_com = comParams.commit(&wallet.as_fr_vec_bar().clone(), &tau_bar);

        let rl_proof = CommitmentProof::<Bls12>::new(
            rng,
            &comParams,
            &rl_com.c,
            &vec![wallet.rev_lock],
            &rho,
            &vec![],
        );

        let xvec: Vec<G1> = vec![rl_proof.T.clone(), rl_com.c];
        let challenge = util::hash_g1_to_fr::<Bls12>(&xvec);
        assert_eq!(
            rl_proof.verify_proof(&comParams, &rl_com.c, &challenge, None),
            true
        );

        let s_proof = CommitmentProof::<Bls12>::new(
            rng,
            &comParams,
            &s_com.c,
            &wallet.as_fr_vec(),
            &tau,
            &vec![],
        );

        let xvec: Vec<G1> = vec![s_proof.T.clone(), s_com.c];
        let challenge = util::hash_g1_to_fr::<Bls12>(&xvec);
        assert_eq!(
            s_proof.verify_proof(&comParams, &s_com.c, &challenge, None),
            true
        );

        let s_bar_proof = CommitmentProof::<Bls12>::new(
            rng,
            &comParams,
            &s_bar_com.c,
            &wallet.as_fr_vec_bar(),
            &tau_bar,
            &vec![],
        );

        let xvec: Vec<G1> = vec![s_bar_proof.T.clone(), s_bar_com.c];
        let challenge = util::hash_g1_to_fr::<Bls12>(&xvec);
        assert_eq!(
            s_bar_proof.verify_proof(&comParams, &s_bar_com.c, &challenge, None),
            true
        );
    }

    #[test]
    fn test_cs_multiparam_serialization() {
        let mut vec: Vec<u8> = Vec::new();
        let bin_g1 = vec![
            132, 83, 99, 124, 75, 72, 15, 109, 12, 94, 84, 103, 1, 58, 160, 232, 190, 23, 119, 195,
            112, 161, 152, 141, 178, 29, 141, 61, 227, 246, 215, 157, 140, 190, 100, 18, 248, 141,
            57, 222, 12, 209, 191, 158, 143, 155, 87, 255,
        ];
        let bin_g2 = vec![
            140, 16, 244, 244, 135, 28, 18, 94, 46, 64, 233, 195, 218, 147, 238, 170, 46, 164, 50,
            92, 234, 117, 61, 158, 64, 226, 153, 38, 127, 168, 49, 125, 177, 183, 74, 164, 138,
            128, 168, 84, 137, 67, 21, 179, 124, 88, 194, 239,
        ];
        let bin_g3 = vec![
            147, 174, 242, 238, 231, 127, 9, 120, 16, 9, 191, 238, 60, 57, 106, 34, 198, 62, 28,
            183, 77, 170, 27, 116, 36, 75, 242, 26, 242, 23, 213, 31, 186, 21, 141, 219, 59, 104,
            247, 118, 56, 95, 183, 124, 103, 83, 93, 154,
        ];

        let ser_g1 = util::encode_as_hexstring(&bin_g1);
        let ser_g2 = util::encode_as_hexstring(&bin_g2);
        let ser_g3 = util::encode_as_hexstring(&bin_g3);

        let str_g1 = ser_g1.as_bytes();
        let str_g2 = ser_g2.as_bytes();
        let str_g3 = ser_g3.as_bytes();

        vec.extend(str_g1);
        vec.extend(str_g2);
        vec.extend(str_g3);

        let rec_csparams = CSMultiParams::<Bls12>::from_slice(&vec.as_slice(), str_g1.len(), 3);
        println!("CS params: {:?}", rec_csparams.pub_bases);

        let ser_cs = serde_json::to_string(&rec_csparams).unwrap();

        println!("Serialized: {:}", ser_cs);
        let rec_g1_str = serde_json::to_string(&rec_csparams.pub_bases[0]).unwrap();
        assert_eq!(rec_g1_str, "\"8453637c4b480f6d0c5e5467013aa0e8be1777c370a1988db21d8d3de3f6d79d8cbe6412f88d39de0cd1bf9e8f9b57ff\"");

        let rec_g2_str = serde_json::to_string(&rec_csparams.pub_bases[1]).unwrap();
        assert_eq!(rec_g2_str, "\"8c10f4f4871c125e2e40e9c3da93eeaa2ea4325cea753d9e40e299267fa8317db1b74aa48a80a854894315b37c58c2ef\"");

        let rec_g3_str = serde_json::to_string(&rec_csparams.pub_bases[2]).unwrap();
        assert_eq!(rec_g3_str, "\"93aef2eee77f09781009bfee3c396a22c63e1cb74daa1b74244bf21af217d51fba158ddb3b68f776385fb77c67535d9a\"");
    }
}
