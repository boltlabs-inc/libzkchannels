use HashSet;
use super::*;
use crypto;
use pairing::Engine;
use rand::Rng;
use util;
use zkproofs;
use zkproofs::{ChannelState, ChannelToken, Commitment, CommitmentProof};
use ff::{Rand,Field};
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
    pub(crate) invoice: Commitment<E>,
    pub(crate) inv_proof: Option<CommitmentProof<E>>,
    pub(crate) claim_proof: Option<(Signature<E>, SignatureProof<E>, Signature<E>, SignatureProof<E>)>,
    pub(crate) nonce: Option<E::Fr>,
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
    fn init(&self, payment_amount: i64, ei: &mut ExtensionInfoWrapper<E>) -> Result<(), String> where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
        <E as pairing::Engine>::Fqk: serde::Serialize,
    {
        let info = match ei {
            ExtensionInfoWrapper::Intermediary(info) => info,
            _ => return Err("wrong extension info".to_string())
        };
        match (&self.inv_proof, &self.claim_proof, self.nonce) {
            (Some(proof), None, None) => {
                let xvec: Vec<E::G1> = vec![proof.T, self.invoice.c];
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
            (None, Some(proof), Some(n)) => {
                // name parts of proof
                let (inv_signature, inv_proof, ac_signature, ac_proof) = proof;

                // check that nonce matches proof
                let challenge = IntermediaryCustomer::fs_challenge(&info.mpk, &inv_proof.a, &ac_proof.a);
                let mut cn = E::Fr::one();
                cn.mul_assign(&challenge);
                cn.mul_assign(&n);
                if cn != inv_proof.zsig[1] {
                    return Err("Nonce does not match commitment".to_string());
                }

                // check that payment amount matches proof
                let mut c_eps = E::Fr::one();
                c_eps.mul_assign(&challenge);
                c_eps.mul_assign(&util::convert_int_to_fr::<E>(-payment_amount));
                if c_eps != inv_proof.zsig[0] {
                    let err = "Payment amount does not match commitment. Maybe it should be negative?";
                    return Err(err.to_string());
                }

                // check if nonce has been seen before and save if not
                let nstr = match serde_json::to_string(&n) {
                    Ok(nstr) => nstr,
                    Err(e) => return Err(format!("Poorly formed nonce: {}", e)),
                };
                if info.nonces.contains(&nstr) {
                    return Err("Nonce has already been redeemed".to_string());
                }
                if !info.nonces.insert(nstr) {
                    return Err("Failed to save nonce".to_string());
                }

                // check that provider IDs match in invoice and credential
                if inv_proof.zsig[2] != ac_proof.zsig[0] {
                    return Err("Provider credentials don't match".to_string());
                }

                // check redemption invoice
                if !info.keypair_inv.public.verify_proof(&info.mpk, &inv_signature, &inv_proof, challenge) ||
                    !info.keypair_ac.public.verify_proof(&info.mpk, &ac_signature, &ac_proof, challenge) {
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
    fn output<R: Rng>(&self, rng: &mut R, ei: &ExtensionInfoWrapper<E>) -> Result<String, String> where
        <E as pairing::Engine>::G1: serde::Serialize,
    {
        let info = match ei {
            ExtensionInfoWrapper::Intermediary(info) => info,
            _ => return Err("wrong extension info".to_string())
        };
        let signature = info.keypair_inv.sign_blind(rng, &info.mpk, &self.invoice);
        match serde_json::to_string(&signature) {
            Ok(output) => Ok(output),
            Err(e) => Err(e.to_string())
        }
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
    /// list of intermediary nonces
    nonces: HashSet<String>,
}

/// Intermediary node; acts as a zkChannels merchant; can pass payments among its customers
pub struct IntermediaryMerchant<E: Engine> {
    /// zkChannel merchant state
    /// this must contain an extension with additional key pairs used by intermediary
    pub merch_state: zkproofs::MerchantState<E>,
    /// channel state information (public parameters, etc)
    pub channel_state: zkproofs::ChannelState<E>,
}

impl<E: Engine> IntermediaryMerchant<E> {
    pub fn init<'a, R: Rng>(
        csprng: &mut R,
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
            nonces: HashSet::new(),
        };
        merch_state.add_extensions_info("intermediary".to_string(), ExtensionInfoWrapper::Intermediary(intermediary_keys));

        (
            IntermediaryMerchant {
                merch_state,
                channel_state,
            },
            channel_token,
        )
    }

    fn get_intermediary_keys(&self) -> &IntermediaryMerchantInfo<E> {
        let ei = self.merch_state.extensions_info.get("intermediary");
        match ei {
            Some(ExtensionInfoWrapper::Intermediary(info)) => info,
            _ => panic!("Intermediary extension info is invalid."),
        }
    }

    /// registers a merchant with the intermediary given a merchant id
    pub fn register_merchant<R: Rng>(&self,
                                     rng: &mut R,
                                     id: E::Fr,
    ) -> crypto::pssig::Signature<E> {
        //TODO: merchant verification?
        self.get_intermediary_keys().keypair_ac.secret.sign(rng, &vec![id])
    }

    /// produces the public key (generators) for the invoice keypair
    pub fn get_invoice_public_keys(&self) -> IntermediaryCustomerInfo<E> {
        let mpk = &self.get_intermediary_keys().mpk;
        IntermediaryCustomerInfo {
            mpk: mpk.clone(),
            invoice_commit: self
                .get_intermediary_keys()
                .keypair_inv
                .generate_cs_multi_params(mpk),
            pub_key_inv: self.get_intermediary_keys().keypair_inv.public.clone(),
            pub_key_ac: self.get_intermediary_keys().keypair_ac.public.clone(),
        }
    }

    /// Unblinds a signature on an invoice using the merchant public keys
    pub fn unblind_invoice(
        &self,
        sig: &Signature<E>,
        bf: &E::Fr,
    ) -> zkproofs::Signature<E> {
        self.get_intermediary_keys()
            .keypair_inv
            .unblind(bf, sig)
    }
}

pub struct IntermediaryCustomerInfo<E: Engine> {
    /// merchant public keys (general, commitment, signing)
    pub(crate) mpk: zkproofs::PublicParams<E>,
    pub(crate) invoice_commit: crypto::ped92::CSMultiParams<E>,
    pub(crate) pub_key_inv: crypto::pssig::BlindPublicKey<E>,
    pub(crate) pub_key_ac: crypto::pssig::BlindPublicKey<E>,
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
    pub intermediary_keys: IntermediaryCustomerInfo<E>,
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
            channel_state,
            merch_id,
            merch_ac: None,
            intermediary_keys,
        }
    }

    pub fn make_invoice<R: Rng>(
        &self,
        payment_amount: i64,
        rng: &mut R,
    ) -> Result<Invoice<E>, String> 
    {
        let provider_id = match self.merch_id {
            Some(id) => id,
            None => 
                return Err("Customer must be a merchant to create an invoice".to_string()),
        };
        let nonce = util::convert_int_to_fr::<E>(rng.gen());
        Ok(Invoice {
            amount: payment_amount,
            nonce,
            provider_id,
        })
    }

    /// Produces a commitment to an invoice
    /// and a NIZK-PoK of the opening of the commitment
    pub fn prepare_payment_invoice<R: Rng>(
        &self,
        invoice: &Invoice<E>,
        rng: &mut R,
    ) -> (Intermediary<E>, E::Fr) {
        let r = util::convert_int_to_fr::<E>(rng.gen());
        let message = invoice.as_fr();
        let commit_key = &self.intermediary_keys.invoice_commit;
        let invoice_commit = commit_key.commit(&message, &r);

        // PoK: prover knows the opening of the commitment
        // and reveals the invoice amount
        let proof =
            CommitmentProof::new(rng, commit_key, &invoice_commit.c, &message, &r, &vec![0]);
        (Intermediary {
            invoice: invoice_commit,
            inv_proof: Some(proof),
            claim_proof: None,
            nonce: None,
        }, r)
    }

    pub fn fs_challenge(mpk: &PublicParams<E>, a1: &E::Fqk, a2: &E::Fqk) -> E::Fr
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

    /// constructs a redemption intermediary with joint proof of knowledge
    /// on the caller's merchant credentials and the given invoice/signature pair
    /// does not validate input (e.g. the invoice does not have to match the signature)
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

        // commit to ac signature (this also blinds it)
        let merch_ac = self.merch_ac.as_ref().unwrap();
        let proof_state_ac = self.intermediary_keys.pub_key_ac.prove_commitment(rng, &self.intermediary_keys.mpk, &merch_ac, None, None);

        // commit to invoice, using the same randomness for the credential field (this also blinds the signature)
        let randomness = Some(vec![E::Fr::zero(), E::Fr::zero(), proof_state_ac.t[0]]);
        let proof_state_inv = self.intermediary_keys.pub_key_inv.prove_commitment(rng, &self.intermediary_keys.mpk, &invoice_sig, randomness, None);

        // set challenge on the /\ of the two commitments
        let challenge = Self::fs_challenge(&self.intermediary_keys.mpk, &proof_state_inv.a, &proof_state_ac.a);

        // calculate response to challenge
        let proof_inv = self.intermediary_keys.pub_key_inv.prove_response(&proof_state_inv, &challenge, &mut message);
        let proof_ac = self.intermediary_keys.pub_key_ac.prove_response(&proof_state_ac, &challenge, &mut vec![self.merch_id.unwrap()]);

        // compose complete PoK: 2 commitments + challenge responses
        Intermediary {
            invoice: invoice_commit,
            inv_proof: None,
            claim_proof: Some((proof_state_inv.blindSig, proof_inv, proof_state_ac.blindSig, proof_ac)),
            nonce: Some(invoice.nonce),
        }
    }

    pub fn validate_invoice_signature(
        &self,
        invoice: &Invoice<E>,
        signature: &crypto::pssig::Signature<E>,
    ) -> bool {
        self.intermediary_keys.pub_key_inv.get_pub_key().verify(
            &self.intermediary_keys.mpk,
            &invoice.as_fr(),
            signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use extensions::extension::Extensions;
    use ff::Rand;
    use pairing::bls12_381::{Bls12, Fr};
    use rand::thread_rng;

    fn make_parties<R: Rng>(rng: &mut R) 
    -> (IntermediaryMerchant<Bls12>, IntermediaryCustomer<Bls12>, IntermediaryCustomer<Bls12>) {
        let merch_name = "Hub";
        let (int_merch, mut channel_token) =
            intermediary::IntermediaryMerchant::<Bls12>::init(rng, merch_name);

        let alice = intermediary::IntermediaryCustomer::init(
            rng,
            &mut channel_token,
            int_merch.get_invoice_public_keys(),
            int_merch.channel_state.clone(),
            1000,
            1000,
            "Alice",
            false,
        );
        let mut bob = intermediary::IntermediaryCustomer::init(
            rng,
            &mut channel_token,
            int_merch.get_invoice_public_keys(),
            int_merch.channel_state.clone(),
            1000,
            1000,
            "bob",
            true,
        );
        let ac = int_merch.register_merchant(rng, bob.merch_id.unwrap());
        bob.merch_ac = Some(ac);

        (int_merch, alice, bob)
    }

    fn get_random_intermediary(with_nonce: bool) -> Intermediary<Bls12> {
        let rng = &mut thread_rng();
        let (int_merch, alice, bob) = make_parties(rng);
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();

        if with_nonce {
            let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
            bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng)
        } else {
            let (intermediary, _) = alice.prepare_payment_invoice(&invoice, rng);
            intermediary
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
    fn intermediary_encoding_works() {
        // encode random value as json string
        for int_type in vec![true, false] {
            let original = get_random_intermediary(int_type);
            let aux = original.to_aux_string();
            
            // convert back
            let result = match serde_json::from_str::<Extensions<Bls12>>(aux.as_str()) {
                Ok(result) => result,
                Err(e) => panic!("Failed to parse json: {}", e),
            };
            let parsed = match result {
                Extensions::Intermediary(obj) => obj,
                _ => panic!("json parsed to incorrect extension type."),
            };
            // check
            compare_intermediaries(original, parsed);
        }
    }

    #[test]
    #[should_panic]
    fn initial_payment_amount_matches() {
        let rng = &mut rand::thread_rng();
        let (mut int_merch, alice, bob) = make_parties(rng);
        let mut invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();
        let (payment_intermediary, _) = alice.prepare_payment_invoice(&invoice, rng);

        // try to pay with the wrong requested payment
        let result = payment_intermediary.init(
            rng.gen_range(100,500),
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(e) => println!("failed with error {}", e),
            Ok(_) => println!("didn't fail??"),
        }

        // try to pay with an invoice that doesn't match the intermediary
        invoice.amount = rng.gen_range(100,500);
        let result = payment_intermediary.init(
            rng.gen_range(100,500),
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(e) => println!("failed with error {}", e), // expected error
            Ok(_) => println!("didn't fail??"), // TODO: replace with panic
        }
    }

    #[test]
    fn initial_payment_proof_matches() {
        let rng = &mut rand::thread_rng();
        let (mut int_merch, alice, bob) = make_parties(rng);
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();
        let (payment_intermediary, _) = alice.prepare_payment_invoice(&invoice, rng);

        // make a mismatched invoice (proof doesn't match commitment)
        let wrong_invoice = bob.make_invoice(invoice.amount, rng).unwrap();
        let (mut wrong_intermediary, _) = alice.prepare_payment_invoice(&wrong_invoice, rng);
        wrong_intermediary.inv_proof = payment_intermediary.inv_proof;

        // try to pay
        let result = wrong_intermediary.init(
            rng.gen_range(100,500),
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(e) => assert_eq!(e, "could not verify proof"), 
            Ok(_) => println!("didn't fail??"),
        }
    }

    #[test]
    fn initial_payment_proof_validates() {
        let rng = &mut rand::thread_rng();
        let (_, alice, bob) = make_parties(rng);
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();

        // create an invoice validated to the original merchant
        let (payment_intermediary, _) = alice.prepare_payment_invoice(&invoice, rng);

        // try to use it to pay to a different merchant
        let (mut other_merch, _, _) = make_parties(rng);
        let result = payment_intermediary.init(
            rng.gen_range(100,500),
            other_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(_) => (), // allow any error
            Ok(_) => panic!("Merchant verified a proof it didn't sign")
        }
    }
    
    #[test]
    fn redemption_payment_proof_matches() {
        let rng = &mut rand::thread_rng();
        let (mut int_merch, _, bob) = make_parties(rng);
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();

        // simulate first payment: get valid signature on invoice from original merchant
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let redemption_intermediary = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        // make a mismatched invoice (replace proofs, but not signatures)
        let wrong_invoice = bob.make_invoice(invoice.amount, rng).unwrap();
        let wrong_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &wrong_invoice.as_fr());
        let mut wrong_intermediary = bob.prepare_redemption_invoice(&invoice, &wrong_sig, rng);

        wrong_intermediary.claim_proof = 
            match (redemption_intermediary.claim_proof, wrong_intermediary.claim_proof) {
                (Some((_, ac_proof, _, inv_proof)), Some((ac_sig, _, inv_sig, _))) => 
                    Some((ac_sig, ac_proof, inv_sig, inv_proof)),
                _ => None,
            };

        // try to pay
        let result = wrong_intermediary.init(
            -invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(e) => assert_eq!(e, "could not verify proof"), // expected error
            Ok(_) => panic!("Merchant allowed a payment with mismatched signature/proof pairs"),
        }
    }
    #[test]
    fn redemption_payment_proof_validates() {
        let rng = &mut rand::thread_rng();
        let (_, _, bob) = make_parties(rng);
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();
        let (mut other_merch, _, _) = make_parties(rng);

        // simulate first payment: get valid signature on invoice from original merchant
        let unblinded_sig = other_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let redemption_invoice = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        // try to use it to pay to a different merchant
        let result = redemption_invoice.init(
            -invoice.amount,
            other_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(_) => (), // allow any error. proof will probably fail at the first check on nonces
            Ok(_) => panic!("Merchant verified a proof it didn't sign")
        }
    }

    #[test]
    fn redemption_payment_nonces_not_reusable() {
        let rng = &mut rand::thread_rng();

        let (mut int_merch, _, bob) = make_parties(rng);

        // merchant initially has 0 nonces
        match int_merch.merch_state.extensions_info.get("intermediary") {
            Some(ExtensionInfoWrapper::Intermediary(info)) => 
                assert_eq!(0, info.nonces.len()),
            _ => panic!("Bad extension type."),
        };

        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();

        // simulate first payment: get valid signature on invoice
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let redemption_invoice = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        // make second payment
        let result = redemption_invoice.init(
            -invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(e) => panic!("Payment failed?! {}", e),
            Ok(_) => (),
        }

        // after payment, merchant has 1 nonce
        match int_merch.merch_state.extensions_info.get("intermediary") {
            Some(ExtensionInfoWrapper::Intermediary(info)) => 
                assert_eq!(1, info.nonces.len()),
            _ => panic!("Bad extension type."),
        };

        // bob cannot redeem invoice again 
        let result = redemption_invoice.init(
            -invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );
        match result {
            Err(e) => assert_eq!(e, "Nonce has already been redeemed"),
            Ok(_) => panic!("Invoice should not be redeemable")
        };
    }

    #[test]
    fn redemption_payment_nonce_matches() {
        let rng = &mut rand::thread_rng();
        let (mut int_merch, _, bob) = make_parties(rng);
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();

        // simulate first payment: get valid signature on invoice
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let mut redemption_invoice = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        // change the nonce in the validated invoice (zk proof stays the same)
        redemption_invoice.nonce = Some(Fr::rand(rng));

        // try to pay
        let outcome = redemption_invoice.init(
            -invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );

        // expected outcome: init should throw an error
        match outcome {
            Ok(_) => panic!("Proof validated with wrong nonce!"),
            Err(e) => assert_eq!(e, "Nonce does not match commitment"), // expected error
        };
    }

    #[test]
    fn redemption_payment_anon_credential_matches() {
        let rng = &mut rand::thread_rng();
        let (mut int_merch, _, bob) = make_parties(rng);

        // put some trash provider ID into the invoice
        let mut invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();
        invoice.provider_id = Fr::rand(rng);

        // simulate first payment: get valid signature on invoice
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let redemption_invoice = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        // try to pay
        let outcome = redemption_invoice.init(
            -invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );

        // expected outcome: init should throw an error
        match outcome {
            Err(e) => assert_eq!(e, "Provider credentials don't match"), // expected error
            Ok(_) => panic!("Proof validated with wrong anonymous credential!"),
        };

    }

    #[test]
    fn redemption_payment_amount_matches() {
        let rng = &mut rand::thread_rng();
        let (mut int_merch, _, bob) = make_parties(rng);

        // simulate first payment: get valid siganture on original invoice
        let invoice = bob.make_invoice(rng.gen_range(5,100), rng).unwrap();
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());

        // BOB generates a redemption proof for a different payment amount
        let bad_invoice = bob.make_invoice(rng.gen_range(100,500), rng).unwrap();
        let redemption_invoice = bob.prepare_redemption_invoice(&bad_invoice, &unblinded_sig, rng);

        // try to pay
        let outcome = redemption_invoice.init(
            -invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );

        // expected outcome: init should throw an error
        match outcome {
            Ok(_) => panic!("Proof validated with wrong anonymous credential!"),
            Err(e) => if ! e.contains("Payment amount does not match commitment") {
                panic!("Proof failed with wrong error! {}", e)
            },
        };
    }
}

