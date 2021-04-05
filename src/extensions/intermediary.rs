use HashSet;
use super::*;
use crypto;
use pairing::Engine;
use rand::Rng;
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
    fn init(&self, _payment_amount: i64, ei: &mut ExtensionInfoWrapper<E>) -> Result<(), String> where
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
                // check if nonce has been seen before
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

                // check redemption invoice
                let challenge = IntermediaryCustomer::fs_challenge(&info.mpk, &proof.1.a, &proof.3.a);
                if !info.keypair_inv.public.verify_proof(&info.mpk, &proof.0, &proof.1, challenge) ||
                    !info.keypair_ac.public.verify_proof(&info.mpk, &proof.2, &proof.3, challenge) {
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
    // TODO: add list of intermediary nonces
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
        let merch_ac = self.merch_ac.as_ref().unwrap();

        let proof_state_inv = self.intermediary_keys.pub_key_inv.prove_commitment(rng, &self.intermediary_keys.mpk, &invoice_sig, None, None);
        let proof_state_ac = self.intermediary_keys.pub_key_ac.prove_commitment(rng, &self.intermediary_keys.mpk, &merch_ac, Some(vec![proof_state_inv.t[2]]), None);
        let challenge = Self::fs_challenge(&self.intermediary_keys.mpk, &proof_state_inv.a, &proof_state_ac.a);
        let proof1 = self.intermediary_keys.pub_key_inv.prove_response(&proof_state_inv, &challenge, &mut message);
        let proof2 = self.intermediary_keys.pub_key_ac.prove_response(&proof_state_ac, &challenge, &mut vec![self.merch_id.unwrap()]);

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
    use crypto::pssig::{setup};

    fn get_random_intermediary(with_nonce: bool) -> (Intermediary<Bls12>, HashMap<String, ExtensionInfoWrapper<Bls12>>) {
        // get a commitment
        let rng = &mut thread_rng();
        let m1 = vec![Fr::rand(rng)];
        let r = Fr::rand(rng);

        let info = get_key_material();
        let mut extension_info = HashMap::new();
        extension_info.insert("intermediary".to_string(), ExtensionInfoWrapper::Intermediary(info.clone()));

        let com_params = info.keypair_inv
            .generate_cs_multi_params(&info.mpk);
        let invoice = com_params.commit(&m1, &r);

        // get a nonce
        if with_nonce {
            // get a PoK
            let mpk = info.mpk;
            let pair1 = info.keypair_inv;
            let pair2 = info.keypair_ac;
            let mut msg1 = vec![Fr::rand(rng), Fr::rand(rng), Fr::rand(rng)];
            let mut msg2 = vec![Fr::rand(rng)];
            let sig1 = pair1.secret.sign(rng, &msg1);
            let sig2 = pair2.secret.sign(rng, &msg2);
            let ps1 = pair1.public.prove_commitment(rng, &mpk, &sig1, None, None);
            let ps2 = pair2.public.prove_commitment(rng, &mpk, &sig2, None, None);
            let challenge = IntermediaryCustomer::fs_challenge(&mpk, &ps1.a, &ps2.a);
            let proof1 = pair1.public.prove_response(&ps1, &challenge, &mut msg1);
            let proof2 = pair2.public.prove_response(&ps2, &challenge, &mut msg2);

            (Intermediary {
                invoice,
                inv_proof: None,
                claim_proof: Some((ps1.blindSig, proof1, ps2.blindSig, proof2)),
                nonce: Some(Fr::rand(rng)),
            }, extension_info)
        } else {
            // get a PoK
            let proof = CommitmentProof::new(rng, &com_params, &invoice.c, &m1, &r, &vec![0]);

            (Intermediary {
                invoice,
                inv_proof: Some(proof),
                claim_proof: None,
                nonce: None,
            }, extension_info)
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
        let (original, mut extension_info) = get_random_intermediary(true);
        let aux = original.to_aux_string();

        // convert back

        let result = match Extensions::parse(&aux, 0, &mut extension_info).unwrap().unwrap() {
            Extensions::Intermediary(obj) => obj,
            _ => panic!("{}", "wrong extension type".to_string()),
        };

        // check
        compare_intermediaries(original, result);
    }

    #[test]
    fn test_encoding_no_nonce() {
        // encode random value WITHOUT A NONCE to json string
        let (original, mut extension_info) = get_random_intermediary(false);
        let aux = original.to_aux_string();

        // convert back
        let result = match Extensions::parse(&aux, 0, &mut extension_info).unwrap().unwrap() {
            Extensions::Intermediary(obj) => obj,
            _ => panic!("{}", "wrong extension type".to_string()),
        };

        // check
        compare_intermediaries(original, result);
    }

    fn get_key_material() -> IntermediaryMerchantInfo<Bls12> {
        let rng = &mut rand::thread_rng();
        let mpk = setup(rng);
        let keypair_ac = crypto::pssig::BlindKeyPair::<Bls12>::generate(rng, &mpk, 1);
        let keypair_inv = crypto::pssig::BlindKeyPair::<Bls12>::generate(rng, &mpk, 3);
        IntermediaryMerchantInfo {
            mpk,
            keypair_ac,
            keypair_inv,
            nonces: HashSet::new(),
        }
    }

    #[test]
    fn nonces_update_correctly() {
        let rng = &mut rand::thread_rng();

        let merch_name = "Hub";
        let (mut int_merch, mut channel_token) =
            intermediary::IntermediaryMerchant::<Bls12>::init(rng, merch_name);

        // merchant initially has 0 nonces
        let info = match int_merch.merch_state.extensions_info.get("intermediary") {
            Some(ExtensionInfoWrapper::Intermediary(info)) => info,
            _ => panic!("Bad extension type."),
        };
        assert_eq!(0, info.nonces.len());

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

        let invoice = intermediary::Invoice::new(
            rng.gen_range(5, 100), // amount
            Fr::rand(rng),         // nonce
            Fr::rand(rng),         // provider id (merchant anon credential)
        );

        // skip straight to second payment
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let redemption_invoice = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        let _ = redemption_invoice.init(
            invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );

        // after payment, merchant has 1 nonce
        let info = match int_merch.merch_state.extensions_info.get("intermediary") {
            Some(ExtensionInfoWrapper::Intermediary(info)) => info,
            _ => panic!("Bad extension type."),
        };
        assert_eq!(1, info.nonces.len());

        // bob cannot redeem invoice again 
        let result = redemption_invoice.init(
            invoice.amount,
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
    fn nonce_verifies_correctly() {
        let rng = &mut rand::thread_rng();

        let merch_name = "Hub";
        let (mut int_merch, mut channel_token) =
            intermediary::IntermediaryMerchant::<Bls12>::init(rng, merch_name);

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

        let invoice = intermediary::Invoice::new(
            rng.gen_range(5, 100), // amount
            Fr::rand(rng),         // nonce
            Fr::rand(rng),         // provider id (merchant anon credential)
        );

        // skip straight to second payment
        let unblinded_sig = int_merch.get_intermediary_keys().keypair_inv.sign(rng, &invoice.as_fr());
        let mut redemption_invoice = bob.prepare_redemption_invoice(&invoice, &unblinded_sig, rng);

        // change the nonce in the validated invoice (zk proof stays the same)
        redemption_invoice.nonce = Some(Fr::rand(rng));

        // try to pay
        let outcome = redemption_invoice.init(
            invoice.amount,
            int_merch.merch_state.extensions_info
                .get_mut("intermediary")
                .expect("Merchant is incorrectly formed (should have an intermediary extension)")
        );

        // expected outcome: init should throw an error
        match outcome {
            Ok(_) => panic!("Proof validated with wrong nonce!"),
            Err(e) => println!("Proof failed with error: {}", e),
        };

    }
}
