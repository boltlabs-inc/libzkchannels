use super::*;
use crypto;
use pairing::Engine;
use rand::{Rng, thread_rng};
use util;
use zkproofs;
use zkproofs::{ChannelState, ChannelToken, Commitment, CommitmentProof};
use ff::Rand;
use crypto::pssig::{Signature, SignatureProof, PublicParams};

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
/// Auxiliary intermediary information
/// (passed as input and output to pay functionality)
/// An Intermediary should hold either an inv_proof OR a claim proof and nonce
pub struct Intermediary<E: Engine> {
    invoice: Commitment<E>,
    inv_proof: Option<CommitmentProof<E>>,
    claim_proof: Option<(Signature<E>, SignatureProof<E>, Signature<E>, SignatureProof<E>)>,
    nonce: Option<E::Fr>,
}

impl<E: Engine> Intermediary<E> {
    pub fn to_aux_string(&self) -> String
        where
            <E as pairing::Engine>::G1: serde::Serialize,
            <E as pairing::Engine>::G2: serde::Serialize,
            <E as ff::ScalarEngine>::Fr: serde::Serialize,
            <E as pairing::Engine>::Fqk: serde::Serialize,
    {
        String::from(
            "{\"type\": \"intermediary\", \"invoice\": ".to_owned()
                + serde_json::to_string(&self.invoice).unwrap().as_str()
                + ", \"inv_proof\": "
                + serde_json::to_string(&self.inv_proof).unwrap().as_str()
                + ", \"claim_proof\": "
                + serde_json::to_string(&self.claim_proof).unwrap().as_str()
                + ", \"nonce\": "
                + serde_json::to_string(&self.nonce).unwrap().as_str()
                + "}",
        )
    }

    pub fn is_claim(&self) -> bool {
        self.claim_proof.is_some()
    }
}

impl<'de, E: Engine> ExtensionTrait<'de, E> for Intermediary<E> {
    fn init(&self, _payment_amount: i64, ei: &ExtensionInfoWrapper<E>) -> Result<(), String> where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as pairing::Engine>::Fqk: serde::Serialize,
    {
        let info = match ei {
            ExtensionInfoWrapper::Intermediary(info) => info,
            _ => return Err("wrong extension info".to_string())
        };
        match (&self.inv_proof, &self.claim_proof, self.nonce) {
            (Some(proof), None, None) => {
                let xvec: Vec<E::G1> = vec![proof.T.clone(), self.invoice.c];
                let challenge = util::hash_g1_to_fr::<E>(&xvec);
                let com_params = info.keypair_inv
                    .generate_cs_multi_params(&info.mpk);
                if proof.verify_proof(&com_params, &self.invoice.c, &challenge, None) { //TODO: reveal option for amount
                    Ok(())
                } else {
                    Err("could not verify proof".to_string())
                }
                // check payment invoice
            }
            (None, Some(proof), Some(_n)) => {
                // check if nonce has been seen before
                /*
            let nonces = HashSet::new(); // TODO: replace this with the actual set of nonces from IntermediaryMerchantInfo
            //let nint = n.from_repr().expect("Badly formed nonce"); // TODO: figure out if field elements have a hashable representation
            if nonces.contains(nint) {
                panic!("Nonce has already been redeemed.".to_string());
            }
            nonces.insert(nint);
            */

                // check redemption invoice
                let challenge = IntermediaryCustomer::fs_challenge(&info.mpk, proof.1.a.clone(), proof.3.a.clone());
                if !info.keypair_inv.public.verify_proof(&info.mpk, proof.0.clone(), proof.1.clone(), challenge) ||
                    !info.keypair_ac.public.verify_proof(&info.mpk, proof.2.clone(), proof.3.clone(), challenge) {
                    return Err("could not verify proof".to_string());
                }
                Ok(())
            }
            _ => {
                Err("Incorrectly formed Intermediary struct.".to_string())
            }
        }
    }

    /// Returns blind signature on invoice commitment
    fn output(&self, ei: &ExtensionInfoWrapper<E>) -> Result<String, String> {
        let info = match ei {
            ExtensionInfoWrapper::Intermediary(info) => info,
            _ => return Err("wrong extension info".to_string())
        };
        let signature = info.keypair_inv.sign_blind(&mut thread_rng(), &info.mpk, self.invoice.clone()); //TODO: pass in rng instead of thread_rng()
        Ok(signature.to_string())
    }
}

/// Invoice object
pub struct Invoice<E: Engine> {
    pub amount: i64,
    pub nonce: E::Fr,
    // provider id is an anonymous credential
    provider_id: E::Fr,
}

impl<E: Engine> Invoice<E> {
    pub fn new(amount: i64, nonce: E::Fr, provider_id: E::Fr) -> Self {
        Invoice {
            amount,
            nonce,
            provider_id,
        }
    }
    pub fn as_fr(&self) -> Vec<E::Fr> {
        vec![
            util::convert_int_to_fr::<E>(self.amount),
            self.nonce,
            self.provider_id,
        ]
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]
pub struct IntermediaryMerchantInfo<E: Engine> {
    /// merchant public parameters
    mpk: zkproofs::PublicParams<E>,
    /// additional keys for handling anonymous credentials
    keypair_ac: crypto::pssig::BlindKeyPair<E>,
    /// additional keys for handling invoices
    keypair_inv: crypto::pssig::BlindKeyPair<E>,
    // TODO: add list of intermediary nonces
    // nonces: HashSet<E::Fr>,
}

/// Intermediary node; acts as a zkChannels merchant; can pass payments among its customers
/// Holds extra key material for generating objects used in intermediary protocol
pub struct IntermediaryMerchant<E: Engine> {
    /// zkChannel merchant state
    pub merch_state: zkproofs::MerchantState<E>,
    /// channel state information (public parameters, etc)
    pub channel_state: zkproofs::ChannelState<E>,
    /// extra key information
    intermediary_keys: IntermediaryMerchantInfo<E>,
}

impl<E: Engine> IntermediaryMerchant<E> {
    pub fn init<'a, R: Rng>(
        csprng: &mut R,
        //channel_state: &mut ChannelState<E>,
        name: &'a str,
    ) -> (Self, ChannelToken<E>) {
        let mut channel_state =
            zkproofs::ChannelState::<E>::new(String::from("an intermediary node"));

        let (channel_token, mut merch_state) =
            zkproofs::merchant_init(csprng, &mut channel_state, name);

        // create additional keys used in intermediary protocol
        let mpk = channel_token.mpk.clone();
        let keypair_ac = crypto::pssig::BlindKeyPair::<E>::generate(csprng, &mpk, 1);
        let keypair_inv = crypto::pssig::BlindKeyPair::<E>::generate(csprng, &mpk, 3);
        let intermediary_keys = IntermediaryMerchantInfo {
            mpk,
            keypair_ac,
            keypair_inv,
            // nonces: HashSet::new(),
        };
        merch_state.add_extensions_info("intermediary".to_string(), ExtensionInfoWrapper::Intermediary(intermediary_keys.clone()));

        (
            IntermediaryMerchant {
                merch_state,
                channel_state,
                intermediary_keys,
            },
            channel_token,
        )
    }

    /// registers a merchant with the intermediary given a merchant id
    pub fn register_merchant<R: Rng>(&self,
                                     rng: &mut R,
                                     id: E::Fr,
    ) -> crypto::pssig::Signature<E> {
        //TODO: merchant verification?
        self.intermediary_keys.keypair_ac.secret.sign(rng, &vec![id])
    }

    /// produces the public key (generators) for the invoice keypair
    pub fn get_invoice_public_keys(&self) -> IntermediaryCustomerInfo<E> {
        let mpk = &self.intermediary_keys.mpk;
        IntermediaryCustomerInfo {
            mpk: mpk.clone(),
            invoice_commit: self
                .intermediary_keys
                .keypair_inv
                .generate_cs_multi_params(mpk),
            pub_key_inv: self.intermediary_keys.keypair_inv.public.clone(),
            pub_key_ac: self.intermediary_keys.keypair_ac.public.clone(),
        }
    }

    /// signs an invoice, not blind
    /// this should probably only be used for testing.
    pub fn sign_invoice<R: Rng>(
        &self,
        invoice: &Invoice<E>,
        rng: &mut R,
    ) -> zkproofs::Signature<E> {
        self.intermediary_keys
            .keypair_inv
            .sign(rng, &invoice.as_fr())
    }
}

pub struct IntermediaryCustomerInfo<E: Engine> {
    /// merchant public keys (general, commitment, signing)
    mpk: zkproofs::PublicParams<E>,
    invoice_commit: crypto::ped92::CSMultiParams<E>,
    pub_key_inv: crypto::pssig::BlindPublicKey<E>,
    pub_key_ac: crypto::pssig::BlindPublicKey<E>,
}

/// Intermediary customer; acts as a zkChannels customer
/// makes payments via an IntermediaryMerchant
/// Holds extra key material from IM.
pub struct IntermediaryCustomer<E: Engine> {
    /// holds the customer state
    pub cust_state: zkproofs::CustomerState<E>,
    /// channel state information (public parameters, etc)
    pub channel_state: zkproofs::ChannelState<E>,
    /// Merchant id if this is indeed a merchant in the intermediary setting
    pub merch_id: Option<E::Fr>,
    /// Merchant anonymous credential if this is indeed a merchant in the intermediary setting
    pub merch_ac: Option<crypto::pssig::Signature<E>>,
    /// intermediary public keys
    intermediary_keys: IntermediaryCustomerInfo<E>,
}

impl<E: Engine> IntermediaryCustomer<E> {
    pub fn init<'a, R: Rng>(
        csprng: &mut R,
        channel_token: &mut ChannelToken<E>,
        intermediary_keys: IntermediaryCustomerInfo<E>,
        channel_state: ChannelState<E>,
        cust_balance: i64,
        merch_balance: i64,
        name: &'a str,
        is_merchant: bool,
    ) -> Self
        where
            <E as pairing::Engine>::G1: serde::Serialize,
            <E as pairing::Engine>::G2: serde::Serialize,
            <E as ff::ScalarEngine>::Fr: serde::Serialize,
    {
        let cust_state =
            zkproofs::customer_init(csprng, channel_token, cust_balance, merch_balance, name);
        let merch_id = if is_merchant {
            Some(E::Fr::rand(csprng))
        } else {
            None
        };

        IntermediaryCustomer {
            cust_state,
            channel_state: channel_state.clone(),
            merch_id,
            merch_ac: None,
            intermediary_keys,
        }
    }

    /// Produces a commitment to an invoice
    /// and a NIZK-PoK of the opening of the commitment
    pub fn prepare_payment_invoice<R: Rng>(
        &self,
        invoice: &Invoice<E>,
        rng: &mut R,
    ) -> Intermediary<E> {
        let r = util::convert_int_to_fr::<E>(rng.gen());
        let message = invoice.as_fr();
        let commit_key = &self.intermediary_keys.invoice_commit;
        let invoice_commit = commit_key.commit(&message, &r);

        // PoK: prover knows the opening of the commitment
        // and reveals the invoice amount
        let proof =
            CommitmentProof::new(rng, commit_key, &invoice_commit.c, &message, &r, &vec![0]);
        Intermediary {
            invoice: invoice_commit,
            inv_proof: Some(proof),
            claim_proof: None,
            nonce: None,
        }
    }

    fn fs_challenge(mpk: &PublicParams<E>, a1: E::Fqk, a2: E::Fqk) -> E::Fr
        where
            <E as pairing::Engine>::G1: serde::Serialize,
            <E as pairing::Engine>::G2: serde::Serialize,
            <E as pairing::Engine>::Fqk: serde::Serialize,
    {
        let mut transcript: Vec<u8> = Vec::new();
        transcript.extend(
            serde_json::to_value(&mpk.g1)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );
        transcript.extend(
            serde_json::to_value(&mpk.g2)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );
        transcript.extend(
            serde_json::to_value(&a1)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );
        transcript.extend(
            serde_json::to_value(&a2)
                .unwrap()
                .as_str()
                .unwrap()
                .bytes(),
        );

        util::hash_to_fr::<E>(transcript)
    }

    pub fn prepare_redemption_invoice<R: Rng>(
        &self,
        invoice: &Invoice<E>,
        invoice_sig: &Signature<E>,
        rng: &mut R,
    ) -> Intermediary<E>
        where
            <E as pairing::Engine>::G1: serde::Serialize,
            <E as pairing::Engine>::G2: serde::Serialize,
            <E as pairing::Engine>::Fqk: serde::Serialize,
    {
        let r = util::convert_int_to_fr::<E>(rng.gen());
        let commit_key = &self.intermediary_keys.invoice_commit;
        let mut message = invoice.as_fr();
        let invoice_commit = commit_key.commit(&message, &r);

        // PoK: prover knows the opening of the commitment
        // and reveals the invoice amount and nonce
        let merch_ac = self.merch_ac.clone().unwrap();

        let proof_state_inv = self.intermediary_keys.pub_key_inv.prove_commitment(rng, &self.intermediary_keys.mpk, &invoice_sig.clone(), None, None);
        let proof_state_ac = self.intermediary_keys.pub_key_ac.prove_commitment(rng, &self.intermediary_keys.mpk, &merch_ac.clone(), Some(vec![proof_state_inv.t[2]]), None);
        let challenge = Self::fs_challenge(&self.intermediary_keys.mpk, proof_state_inv.a, proof_state_ac.a);
        let proof1 = self.intermediary_keys.pub_key_inv.prove_response(&proof_state_inv, challenge, &mut message);
        let proof2 = self.intermediary_keys.pub_key_ac.prove_response(&proof_state_ac, challenge, &mut vec![self.merch_id.unwrap()]);

        Intermediary {
            invoice: invoice_commit,
            inv_proof: None,
            claim_proof: Some((proof_state_inv.blindSig, proof1, proof_state_ac.blindSig, proof2)),
            nonce: Some(invoice.nonce),
        }
    }

    pub fn validate_invoice_signature(
        &self,
        invoice: &Invoice<E>,
        signature: crypto::pssig::Signature<E>,
    ) -> bool {
        self.intermediary_keys.pub_key_inv.get_pub_key().verify(
            &self.intermediary_keys.mpk,
            &invoice.as_fr(),
            &signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ped92::CSMultiParams;
    use extensions::extension::Extensions;
    use ff::Rand;
    use pairing::bls12_381::{Bls12, Fr};
    use rand::thread_rng;

    fn get_random_intermediary(with_nonce: bool) -> Intermediary<Bls12> {
        // get a commitment
        let rng = &mut thread_rng();
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, 5);
        let m1 = vec![Fr::rand(rng)];
        let r = Fr::rand(rng);
        let invoice = csp.commit(&m1, &r);

        // get a PoK
        let proof = CommitmentProof::new(rng, &csp, &invoice.c, &m1, &r, &vec![0]);

        // get a nonce
        let nonce = if with_nonce {
            Some(Fr::rand(rng))
        } else {
            None
        };

        Intermediary {
            invoice,
            inv_proof: Some(proof),
            claim_proof: None,
            nonce,
        }
    }

    fn compare_intermediaries<E: Engine>(original: Intermediary<E>, result: Intermediary<E>) {
        assert!(result.invoice == original.invoice);
        // NOTE: couldn't figure out how to compare proofs
        // assert_eq!(result.proof, original.proof);
        match (result.nonce, original.nonce) {
            (Some(n1), Some(n2)) => assert!(n1 == n2),
            (None, None) => assert!(true),
            _ => assert!(false),
        };
    }

    #[test]
    fn test_encoding_nonce() {
        // encode random value as json string
        let original = get_random_intermediary(true);
        let aux = original.to_aux_string();

        // convert back
        let result = match Extensions::parse(&aux, 0, HashMap::new()).unwrap().unwrap() {
            Extensions::Intermediary(obj) => obj,
            _ => panic!("{}", "wrong extension type".to_string()),
        };

        // check
        compare_intermediaries(original, result);
    }

    #[test]
    fn test_encoding_no_nonce() {
        // encode random value WITHOUT A NONCE to json string
        let original = get_random_intermediary(false);
        let aux = original.to_aux_string();

        // convert back
        let result = match Extensions::parse(&aux, 0, HashMap::new()).unwrap().unwrap() {
            Extensions::Intermediary(obj) => obj,
            _ => panic!("{}", "wrong extension type".to_string()),
        };

        // check
        compare_intermediaries(original, result);
    }
}
