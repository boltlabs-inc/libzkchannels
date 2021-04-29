use super::*;
use ccs08::{ParamsUL, ProofUL, SecretParamsUL};
use channels_zk::ClosedCommitments;
use cl::{setup, BlindKeyPair, BlindPublicKey, PublicParams, Signature, SignatureProof};
use pairing::{CurveProjective, Engine};
use ped92::{CSMultiParams, Commitment, CommitmentProof};
use rand::Rng;
use serde::{Deserialize, Serialize};
use util;
use wallet::Wallet;

/// NIZKProof is the object that represents the NIZK Proof of Knowledge during the payment and closing protocol
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize, \
                           <E as pairing::Engine>::Fqk: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::Fqk: serde::Deserialize<'de>")
)]
pub struct NIZKProof<E: Engine> {
    pub sig: Signature<E>,
    pub sigProof: SignatureProof<E>,
    pub rlComProof: CommitmentProof<E>,
    pub comProof: CommitmentProof<E>,
    pub comBarProof: CommitmentProof<E>,
    pub rpBC: ProofUL<E>,
    pub rpBM: ProofUL<E>,
}

/// NIZKPublicParams are public parameters to perform a NIZK Proof of Knowledge during the payment and closing protocol
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct NIZKPublicParams<E: Engine> {
    pub mpk: PublicParams<E>,
    pub pk: BlindPublicKey<E>,
    pub comParams: CSMultiParams<E>,
    pub rpParams: ParamsUL<E>,
}

/// NIZKSecretParams are secret parameters to perform the verification of a NIZK Proof of Knowledge during the payment and closing protocol
#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
    bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct NIZKSecretParams<E: Engine> {
    pub pubParams: NIZKPublicParams<E>,
    pub keypair: BlindKeyPair<E>,
    pub rpParams: SecretParamsUL<E>,
}

impl<E: Engine> NIZKSecretParams<E> {
    /// Basic setup for the NIZKPublicParams
    /// Takes as input a random generator and the length of the message which should be 4 during payment protocol and 5 for the closing protocol
    pub fn setup<R: Rng>(rng: &mut R, messageLength: usize) -> Self {
        let mpk = setup(rng);
        let keypair = BlindKeyPair::<E>::generate(rng, &mpk, messageLength);
        let comParams = keypair.generate_cs_multi_params(&mpk);
        let u = 128; //TODO: make u and l configurable
        let l = 9;
        let rpParams = SecretParamsUL::setup_ul(rng, u, l, comParams.clone());
        let pubParams = NIZKPublicParams {
            mpk,
            pk: keypair.public.clone(),
            comParams,
            rpParams: rpParams.pubParams.clone(),
        };

        NIZKSecretParams {
            pubParams,
            keypair,
            rpParams,
        }
    }

    /**
        Verify a NIZK Proof of Knowledge during payment or closing protocol
        Input:
        proof: A NIZK proof created by the Customer
        epsilon: The transaction amount of the payment
        com: Commitment of the new wallet that needs to be signed
        nonce: reveal of the nonce of the old wallet.
    */
    pub fn verify(
        &self,
        proof: NIZKProof<E>,
        epsilon: E::Fr,
        coms: &ClosedCommitments<E>,
        nonce: E::Fr,
    ) -> bool {
        //verify signature is not the identity
        if proof.sig.h == E::G1::zero() {
            return false;
        }

        //compute challenge
        let mut T = self.pubParams.comParams.pub_bases.clone();
        T.append(&mut vec![
            proof.rlComProof.T,
            proof.comProof.T,
            proof.comBarProof.T,
            proof.rpBC.D,
            proof.rpBM.D,
        ]);
        let challenge = NIZKPublicParams::<E>::hash(proof.sigProof.a, T);

        //verify knowledge of signature
        let mut r1 = self.keypair.public.verify_proof(
            &self.pubParams.mpk,
            &proof.sig,
            &proof.sigProof,
            challenge,
        );
        let mut noncec = nonce.clone();
        noncec.mul_assign(&challenge);
        r1 = r1 && proof.sigProof.zsig[1] == noncec;

        //verify knowledge of commitment
        let r2_1 = proof.rlComProof.verify_proof(
            &self.pubParams.comParams,
            &coms.rl_com.c,
            &challenge,
            None,
        );

        let r2_2 =
            proof
                .comProof
                .verify_proof(&self.pubParams.comParams, &coms.s_com.c, &challenge, None);

        let r2_3 = proof.comBarProof.verify_proof(
            &self.pubParams.comParams,
            &coms.s_bar_com.c,
            &challenge,
            None,
        );

        //verify range proofs
        let r3 = self.rpParams.verify_ul(&proof.rpBC, challenge.clone(), 4);
        let r4 = self.rpParams.verify_ul(&proof.rpBM, challenge.clone(), 5);

        //verify linear relationship
        let mut r5 = proof.comProof.z[1] == proof.sigProof.zsig[0];
        let mut zsig2 = proof.sigProof.zsig[3].clone();
        let mut epsC = epsilon.clone();
        epsC.mul_assign(&challenge);
        zsig2.sub_assign(&epsC);
        r5 = r5 && proof.comProof.z[4] == zsig2;
        let mut zsig3 = proof.sigProof.zsig[4].clone();
        zsig3.add_assign(&epsC);
        r5 = r5 && proof.comProof.z[5] == zsig3;

        r5 = r5 && proof.comProof.z[1] == proof.comBarProof.z[1];
        r5 = r5 && proof.comProof.z[3] == proof.comBarProof.z[2];
        r5 = r5 && proof.comProof.z[4] == proof.comBarProof.z[3];
        r5 = r5 && proof.comProof.z[5] == proof.comBarProof.z[4];

        r5 = r5 && proof.rlComProof.z[1] == proof.sigProof.zsig[2];

        r1 && r2_1 && r2_2 && r2_3 && r3 && r4 && r5
    }
}

impl<E: Engine> NIZKPublicParams<E> {
    /** This method can be called to create the proof during the payment and closing protocol
        Input:
        rng: random generator
        oldWallet: This is the wallet before payment occurs
        newWallet: This is the new state of the wallet after payment
        newWalletCom: A commitment of the new wallet
        newRho: blinding value of commitment of new revocation lock
        newTau: blinding value of commitment of new wallet
        newTauBar: blinding value of commitment of new wallet bar
        paymentToken: A blind signature on the old wallet
        Output:
        NIZKProof: a proof that can be verified by the merchant during payment or closing protocol
    */
    pub fn prove<R: Rng>(
        &self,
        rng: &mut R,
        oldWallet: Wallet<E>,
        newWallet: Wallet<E>,
        newWalletCom: Commitment<E>,
        rho: E::Fr,
        newTau: E::Fr,
        newTauBar: E::Fr,
        paymentToken: &Signature<E>,
    ) -> NIZKProof<E> {
        //Commitment phase
        //commit commitment
        let (D1, t1) = CommitmentProof::<E>::prove_commitment(
            rng,
            &self.comParams,
            &vec![oldWallet.rev_lock],
            None,
        );

        let (D2, t2) = CommitmentProof::<E>::prove_commitment(
            rng,
            &self.comParams,
            &newWallet.as_fr_vec(),
            None,
        );

        let t3_0 = E::Fr::rand(rng);
        let (D3, t3) = CommitmentProof::<E>::prove_commitment(
            rng,
            &self.comParams,
            &newWallet.as_fr_vec_bar(),
            Some(vec![t3_0, t2[1], t2[3], t2[4], t2[5]]),
        );

        //commit signature
        let zero = E::Fr::zero();
        let tOptional = Some(vec![t2[1], zero, t1[1], t2[4], t2[5]]);
        let proofState = self
            .pk
            .prove_commitment(rng, &self.mpk, &paymentToken, tOptional, None);

        //commit range proof
        let rpStateBC = self
            .rpParams
            .prove_ul_commitment(rng, newWallet.bc.clone(), 4, None, None);
        let rpStateBM = self
            .rpParams
            .prove_ul_commitment(rng, newWallet.bm.clone(), 5, None, None);

        //Compute challenge
        let mut T = self.comParams.pub_bases.clone();
        T.append(&mut vec![D1, D2, D3, rpStateBC.D, rpStateBM.D]);
        let challenge = NIZKPublicParams::<E>::hash(proofState.a, T);

        //Response phase
        //response for signature
        let mut oldWalletVec = oldWallet.as_fr_vec();
        let sigProof = self
            .pk
            .prove_response(&proofState, challenge, &mut oldWalletVec);

        //response commitment
        let rlComProof = CommitmentProof::<E>::prove_response(
            &vec![oldWallet.rev_lock],
            &rho,
            D1,
            &t1,
            &challenge,
        );
        let newWalletVec = newWallet.as_fr_vec();
        let comProof =
            CommitmentProof::<E>::prove_response(&newWalletVec, &newTau, D2, &t2, &challenge);
        let newWalletBarVec = newWallet.as_fr_vec_bar();
        let comBarProof =
            CommitmentProof::<E>::prove_response(&newWalletBarVec, &newTauBar, D3, &t3, &challenge);

        //response range proof
        let mut vec01 = newWalletVec[0..3].to_vec();
        let mut vecWithout3 = vec01.clone();
        let mut vec3 = newWalletVec[4..].to_vec();
        vecWithout3.append(&mut vec3);
        let vec2 = newWalletVec[3].clone();
        vec01.push(vec2);
        if newWalletVec.len() > 5 {
            let mut vec4 = newWalletVec[5..].to_vec();
            vec01.append(&mut vec4);
        }
        let rpBC = self.rpParams.prove_ul_response(
            newTau.clone(),
            newWalletCom.clone(),
            &rpStateBC,
            challenge.clone(),
            4,
            vecWithout3.to_vec(),
        );
        let rpBM = self.rpParams.prove_ul_response(
            newTau.clone(),
            newWalletCom.clone(),
            &rpStateBM,
            challenge.clone(),
            5,
            vec01.to_vec(),
        );

        NIZKProof {
            sig: proofState.blindSig,
            sigProof,
            rlComProof,
            comProof,
            comBarProof,
            rpBC,
            rpBM,
        }
    }

    fn hash(a: E::Fqk, T: Vec<E::G1>) -> E::Fr {
        let mut x_vec: Vec<u8> = Vec::new();
        x_vec.extend(format!("{}", a).bytes());
        for t in T {
            x_vec.extend(format!("{}", t).bytes());
        }

        util::hash_to_fr::<E>(x_vec)
    }
}

///
/// Verify PoK for the opening of a commitment during the establishment protocol
///
pub fn verify_opening<E: Engine>(
    com_params: &CSMultiParams<E>,
    com: &E::G1,
    proof: &CommitmentProof<E>,
    channelId: &E::Fr,
    init_cust: i64,
    init_merch: i64,
) -> bool {
    let xvec: Vec<E::G1> = vec![proof.T.clone(), com.clone()];
    let challenge = util::hash_g1_to_fr::<E>(&xvec);

    // compute the
    let com_equal = proof.verify_proof(
        com_params,
        com,
        &challenge,
        Some(vec![
            None,
            Some(channelId.clone()),
            None,
            None,
            Some(util::convert_int_to_fr::<E>(init_cust as i64)),
            Some(util::convert_int_to_fr::<E>(init_merch as i64)),
        ]),
    );

    return com_equal;
}

///
/// Verify PoK for the opening of a commitment during the establishment protocol
///
pub fn verify_opening_bar<E: Engine>(
    com_params: &CSMultiParams<E>,
    com: &E::G1,
    proof: &CommitmentProof<E>,
    channelId: &E::Fr,
    init_cust: i64,
    init_merch: i64,
) -> bool {
    let xvec: Vec<E::G1> = vec![proof.T.clone(), com.clone()];
    let challenge = util::hash_g1_to_fr::<E>(&xvec);

    // compute the
    let com_equal = proof.verify_proof(
        com_params,
        com,
        &challenge,
        Some(vec![
            None,
            Some(channelId.clone()),
            None,
            Some(util::convert_int_to_fr::<E>(init_cust as i64)),
            Some(util::convert_int_to_fr::<E>(init_merch as i64)),
        ]),
    );

    return com_equal;
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::PrimeField;
    use pairing::bls12_381::{Bls12, Fr};
    use util::convert_int_to_fr;

    #[test]
    fn nizk_proof_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let nonce2 = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let rl2 = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let tau = Fr::rand(rng);
        let rho = Fr::rand(rng);
        let tau2 = Fr::rand(rng);
        let tau_bar2 = Fr::rand(rng);

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let wallet1 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc,
            bm,
        };
        let s_com1 = secParams
            .pubParams
            .comParams
            .commit(&wallet1.as_fr_vec(), &tau);
        let wallet2 = Wallet {
            channelId: channelId,
            nonce: nonce2,
            rev_lock: rl2,
            bc: bc2,
            bm: bm2,
        };
        let rl_com2 = secParams.pubParams.comParams.commit(&vec![rl], &rho);
        let s_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec(), &tau2);
        let s_bar_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec_bar(), &tau_bar2);
        let blindPaymentToken = secParams
            .keypair
            .sign_blind(rng, &secParams.pubParams.mpk, s_com1);
        let paymentToken = secParams.keypair.unblind(&tau, &blindPaymentToken);

        let proof = secParams.pubParams.prove(
            rng,
            wallet1,
            wallet2,
            s_com2.clone(),
            rho,
            tau2,
            tau_bar2,
            &paymentToken,
        );
        let fr = convert_int_to_fr::<Bls12>(epsilon);
        assert_eq!(
            secParams.verify(
                proof,
                fr,
                &ClosedCommitments {
                    s_com: s_com2,
                    s_bar_com: s_bar_com2,
                    rl_com: rl_com2
                },
                nonce
            ),
            true
        );
    }

    #[test]
    fn nizk_proof_negative_value_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let rlprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(-100, -1);
        bc2 -= epsilon;
        bm2 += epsilon;
        let tau = Fr::rand(rng);
        let rho = Fr::rand(rng);
        let tau2 = Fr::rand(rng);
        let tau_bar2 = Fr::rand(rng);

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let wallet1 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc,
            bm,
        };
        let s_com1 = secParams
            .pubParams
            .comParams
            .commit(&wallet1.as_fr_vec(), &tau);
        let wallet2 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rlprime,
            bc: bc2,
            bm: bm2,
        };
        let rl_com2 = secParams.pubParams.comParams.commit(&vec![rl], &rho);
        let s_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec(), &tau2);
        let s_bar_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec_bar(), &tau_bar2);
        let blindPaymentToken = secParams
            .keypair
            .sign_blind(rng, &secParams.pubParams.mpk, s_com1);
        let paymentToken = secParams.keypair.unblind(&tau, &blindPaymentToken);

        let proof = secParams.pubParams.prove(
            rng,
            wallet1,
            wallet2,
            s_com2.clone(),
            rho,
            tau2,
            tau_bar2,
            &paymentToken,
        );
        let fr = convert_int_to_fr::<Bls12>(epsilon);
        assert_eq!(
            secParams.verify(
                proof,
                fr,
                &ClosedCommitments {
                    s_com: s_com2,
                    s_bar_com: s_bar_com2,
                    rl_com: rl_com2
                },
                nonce
            ),
            true
        );
    }

    #[test]
    fn nizk_proof_close_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let rlprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let tau = Fr::rand(rng);
        let rho = Fr::rand(rng);
        let tau2 = Fr::rand(rng);
        let tau_bar2 = Fr::rand(rng);

        let _closeToken = Fr::rand(rng);
        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let wallet1 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc,
            bm,
        };
        let s_com = secParams
            .pubParams
            .comParams
            .commit(&wallet1.as_fr_vec(), &tau);
        let wallet2 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rlprime,
            bc: bc2,
            bm: bm2,
        };
        let rl_com2 = secParams.pubParams.comParams.commit(&vec![rl], &rho);
        let s_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec(), &tau2);
        let s_bar_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec_bar(), &tau_bar2);
        let blindPaymentToken = secParams
            .keypair
            .sign_blind(rng, &secParams.pubParams.mpk, s_com);
        let paymentToken = secParams.keypair.unblind(&tau, &blindPaymentToken);

        let blindCloseToken =
            secParams
                .keypair
                .sign_blind(rng, &secParams.pubParams.mpk, s_bar_com2.clone());
        let closeToken = secParams.pubParams.pk.unblind(&tau_bar2, &blindCloseToken);

        // verify the blind signatures
        let pk = secParams.keypair.get_public_key(&secParams.pubParams.mpk);
        assert!(pk.verify(
            &secParams.pubParams.mpk,
            &wallet1.as_fr_vec(),
            &paymentToken,
        ));

        println!("close => {}", &wallet2);
        assert!(pk.verify(
            &secParams.pubParams.mpk,
            &wallet2.as_fr_vec_bar(),
            &closeToken
        ));

        let proof = secParams.pubParams.prove(
            rng,
            wallet1,
            wallet2,
            s_com2.clone(),
            rho,
            tau2,
            tau_bar2,
            &paymentToken,
        );

        assert_eq!(
            secParams.verify(
                proof,
                Fr::from_str(&epsilon.to_string()).unwrap(),
                &ClosedCommitments {
                    s_com: s_com2,
                    s_bar_com: s_bar_com2,
                    rl_com: rl_com2
                },
                nonce,
            ),
            true
        );
    }

    #[test]
    fn nizk_proof_false_statements() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let rlprime = Fr::rand(rng);
        let bc = rng.gen_range(100, 1000);
        let mut bc2 = bc.clone();
        let bm = rng.gen_range(100, 1000);
        let mut bm2 = bm.clone();
        let epsilon = rng.gen_range(1, 100);
        bc2 -= epsilon;
        bm2 += epsilon;
        let tau = Fr::rand(rng);
        let rho = Fr::rand(rng);
        let tau2 = Fr::rand(rng);
        let tau_bar2 = Fr::rand(rng);

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let wallet1 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc,
            bm,
        };

        let bc2Prime = bc;
        let wallet3 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rlprime,
            bc: bc2Prime,
            bm: bm2,
        };
        let s_com = secParams
            .pubParams
            .comParams
            .commit(&wallet1.as_fr_vec(), &tau);
        let rl_com2 = secParams.pubParams.comParams.commit(&vec![rl], &rho);
        let s_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet3.as_fr_vec(), &tau2);
        let s_bar_com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet3.as_fr_vec_bar(), &tau_bar2);
        let blindPaymentToken = secParams
            .keypair
            .sign_blind(rng, &secParams.pubParams.mpk, s_com);
        let paymentToken = secParams.keypair.unblind(&tau, &blindPaymentToken);
        let proof = secParams.pubParams.prove(
            rng,
            wallet1.clone(),
            wallet3,
            s_com2.clone(),
            rho,
            tau2,
            tau_bar2,
            &paymentToken,
        );
        assert_eq!(
            secParams.verify(
                proof,
                Fr::from_str(&epsilon.to_string()).unwrap(),
                &ClosedCommitments {
                    s_com: s_com2.clone(),
                    s_bar_com: s_bar_com2.clone(),
                    rl_com: rl_com2.clone()
                },
                nonce,
            ),
            false
        );

        let bm2Prime = bm.clone();
        let wallet4 = Wallet {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rlprime,
            bc: bc2,
            bm: bm2Prime,
        };
        let commitment2 = secParams
            .pubParams
            .comParams
            .commit(&wallet4.as_fr_vec(), &tau2);
        let proof = secParams.pubParams.prove(
            rng,
            wallet1.clone(),
            wallet4,
            commitment2.clone(),
            rho,
            tau2,
            tau_bar2,
            &paymentToken,
        );
        assert_eq!(
            secParams.verify(
                proof,
                Fr::from_str(&epsilon.to_string()).unwrap(),
                &ClosedCommitments {
                    s_com: s_com2.clone(),
                    s_bar_com: s_bar_com2.clone(),
                    rl_com: rl_com2.clone()
                },
                nonce,
            ),
            false
        );

        let wallet5 = Wallet {
            channelId: Fr::rand(rng),
            nonce: Fr::rand(rng),
            rev_lock: rlprime,
            bc: bc2,
            bm: bm2,
        };
        let commitment2 = secParams
            .pubParams
            .comParams
            .commit(&wallet5.as_fr_vec(), &tau2);
        let proof = secParams.pubParams.prove(
            rng,
            wallet1.clone(),
            wallet5,
            commitment2.clone(),
            rho,
            tau2,
            tau_bar2,
            &paymentToken,
        );
        assert_eq!(
            secParams.verify(
                proof,
                Fr::from_str(&epsilon.to_string()).unwrap(),
                &ClosedCommitments {
                    s_com: s_com2,
                    s_bar_com: s_bar_com2,
                    rl_com: rl_com2
                },
                nonce,
            ),
            false
        );
    }

    #[test]
    fn nizk_proof_commitment_opening_works() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let t = Fr::rand(rng);

        let bc = rng.gen_range(100, 1000);
        let bm = rng.gen_range(100, 1000);
        let wallet = Wallet::<Bls12> {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc: bc,
            bm: bm,
        };

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let com = secParams
            .pubParams
            .comParams
            .commit(&wallet.as_fr_vec(), &t);

        let com_proof = CommitmentProof::<Bls12>::new(
            rng,
            &secParams.pubParams.comParams,
            &com.c,
            &wallet.as_fr_vec(),
            &t,
            &vec![1, 4, 5],
        );

        assert!(verify_opening(
            &secParams.pubParams.comParams,
            &com.c,
            &com_proof,
            &channelId,
            bc,
            bm,
        ));
    }

    #[test]
    fn nizk_proof_false_commitment() {
        let rng = &mut rand::thread_rng();
        let channelId = Fr::rand(rng);
        let nonce = Fr::rand(rng);
        let rl = Fr::rand(rng);
        let t = Fr::rand(rng);

        let bc = rng.gen_range(100, 1000);
        let bc2 = rng.gen_range(100, 1000);
        let bm = rng.gen_range(100, 1000);
        let wallet1 = Wallet::<Bls12> {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc: bc,
            bm: bm,
        };
        let wallet2 = Wallet::<Bls12> {
            channelId: channelId,
            nonce: nonce,
            rev_lock: rl,
            bc: bc2,
            bm: bm,
        };

        let secParams = NIZKSecretParams::<Bls12>::setup(rng, 5);
        let com1 = secParams
            .pubParams
            .comParams
            .commit(&wallet1.as_fr_vec(), &t);
        let com2 = secParams
            .pubParams
            .comParams
            .commit(&wallet2.as_fr_vec(), &t);

        let com1_proof = CommitmentProof::<Bls12>::new(
            rng,
            &secParams.pubParams.comParams,
            &com1.c,
            &wallet1.as_fr_vec(),
            &t,
            &vec![1, 4, 5],
        );

        assert!(verify_opening(
            &secParams.pubParams.comParams,
            &com1.c,
            &com1_proof,
            &channelId,
            bc,
            bm,
        ));
        assert!(!verify_opening(
            &secParams.pubParams.comParams,
            &com2.c,
            &com1_proof,
            &channelId,
            bc2,
            bm,
        ));
    }

    #[test]
    fn test_nizk_serialization() {
        let mut rng = &mut rand::thread_rng();

        let l = 5;
        let mpk = setup(&mut rng);
        let blindkeypair = BlindKeyPair::<Bls12>::generate(&mut rng, &mpk, l);
        let comParams = blindkeypair.generate_cs_multi_params(&mpk);
        let u = 256; //TODO: optimize u?
        let l = 8;
        let rpParams = ccs08::SecretParamsUL::setup_ul(rng, u, l, comParams.clone());

        let nizk_params = NIZKPublicParams {
            mpk: mpk,
            pk: blindkeypair.public,
            comParams: comParams,
            rpParams: rpParams.pubParams.clone(),
        };

        let is_serialized = serde_json::to_vec(&nizk_params).unwrap();
        println!("NIZK Struct len: {}", is_serialized.len());

        // deserialize
    }
}
