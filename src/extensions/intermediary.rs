use super::*;
use crypto;
use extensions::ExtensionOutput;
use rand::{Rng};
use pairing::Engine;
use zkproofs::{ChannelToken,ChannelState,Commitment,CommitmentProof};
use zkproofs;
use util;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize, \
                           <E as pairing::Engine>::G1: serde::Serialize, \
                           <E as pairing::Engine>::G2: serde::Serialize"))]
#[serde(
bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G1: serde::Deserialize<'de>, \
                         <E as pairing::Engine>::G2: serde::Deserialize<'de>")
)]

/// Auxiliary intermediary information
/// (passed as input and output to pay functionality)
pub struct Intermediary<E: Engine> {
    invoice: Commitment<E>,
    proof: CommitmentProof<E>,
    nonce: Option<E::Fr>
}

impl<E:Engine> Intermediary<E> {
    pub fn to_aux_string(&self) 
    -> String 
    where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
    {
        String::from("{\"type\": \"intermediary\", \"invoice\": ".to_owned() +
            serde_json::to_string(&self.invoice).unwrap().as_str() +
            ", \"proof\": " +
            serde_json::to_string(&self.proof).unwrap().as_str() +
            ", \"nonce\": " + 
            serde_json::to_string(&self.nonce).unwrap().as_str() + "}" 
        )
    }
}

impl<E: Engine> ExtensionInit for Intermediary<E> {
    fn init(&self) {}
}

impl<E: Engine> ExtensionOutput for Intermediary<E> {
    /// Returns blind signature on invoice commitment
    fn output(&self) -> Result<String, String> {
        Ok("This is a valid blind signature!".to_string())
        // unimplemented!()
    }
}

/// Invoice object
pub struct Invoice<E:Engine> {
    pub amount: i64,
    pub nonce: E::Fr,
    // provider id is an anonymous credential
    provider_id: E::Fr,
}

impl<E:Engine> Invoice<E> {
    pub fn new(amount: i64, nonce: E::Fr, provider_id: E::Fr) -> Self {
        Invoice {
            amount,
            nonce,
            provider_id
        }
    }
    pub fn as_fr(&self) -> Vec<E::Fr> {
        vec![util::convert_int_to_fr::<E>(self.amount), self.nonce, self.provider_id]
    }
}

/// Intermediary node; acts as a zkChannels merchant; can pass payments among its customers
/// Holds extra key material for generating objects used in intermediary protocol
pub struct IntermediaryMerchant<E: Engine> {
    /// zkChannel merchant state
    pub merch_state: zkproofs::MerchantState<E>,
    /// merchant public parameters 
    mpk: zkproofs::PublicParams<E>,
    /// additional keys for handling anonymous credentials
    keypair_ac: crypto::cl::BlindKeyPair<E>,
    /// additional keys for handling invoices
    keypair_inv: crypto::cl::BlindKeyPair<E>,
}

impl<E: Engine> IntermediaryMerchant<E> {
    
    pub fn init<'a, R: Rng>(
        csprng: &mut R,
        channel_state: &mut ChannelState<E>,
        name: &'a str,
    ) -> (Self, ChannelToken<E>, ChannelState<E>) {
        let (channel_token, merch_state, channel_state) =
            zkproofs::merchant_init(csprng, channel_state, name);
        
        // create additional keys used in intermediary protocol
        let mpk = channel_token.mpk.clone();
        let keypair_ac = crypto::cl::BlindKeyPair::<E>::generate(csprng, &mpk, 1);
        let keypair_inv = crypto::cl::BlindKeyPair::<E>::generate(csprng, &mpk, 3);
        
        (IntermediaryMerchant {
            merch_state,
            mpk,
            keypair_ac,
            keypair_inv,
        },
        channel_token,
        channel_state)
    }

    /// produces the public key (generators) for the invoice keypair
    pub fn get_invoice_public_keys(&self) -> IntermediaryMerchantPublicKeys<E> {
        IntermediaryMerchantPublicKeys {
            mpk: self.mpk.clone(),
            invoice_commit: self.keypair_inv.generate_cs_multi_params(&self.mpk),
            invoice_sign: self.keypair_inv.get_public_key(&self.mpk)
        }
    }

    /// signs an invoice, not blind
    /// this should probably only be used for testing.
    pub fn sign_invoice<R: Rng>(
        &self,
        invoice: &Invoice<E>,
        rng: &mut R,
    ) -> zkproofs::Signature<E> {
        self.keypair_inv.sign(rng, &invoice.as_fr())
    }
}

pub struct IntermediaryMerchantPublicKeys<E:Engine> {
    mpk: zkproofs::PublicParams<E>,
    invoice_commit: crypto::ped92::CSMultiParams<E>, 
    invoice_sign: crypto::cl::PublicKey<E>,
}

/// Intermediary customer; acts as a zkChannels customer
/// makes payments via an IntermediaryMerchant
/// Holds extra key material from IM.
pub struct IntermediaryCustomer<E:Engine> {
    /// holds the customer state
    pub cust_state: zkproofs::CustomerState<E>,
    /// merchant public keys 
    merchant_keys: IntermediaryMerchantPublicKeys<E>
}

impl<E: Engine> IntermediaryCustomer<E> {
    pub fn init<'a, R: Rng>(
        csprng: &mut R,
        channel_token: &mut ChannelToken<E>,
        merch: &IntermediaryMerchant<E>,
        cust_balance: i64,
        merch_balance: i64,
        name: &'a str,
    ) -> Self 
    where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
    {
        let cust_state =
            zkproofs::customer_init(csprng, channel_token, cust_balance, merch_balance, name);
        let merchant_keys = merch.get_invoice_public_keys();

        IntermediaryCustomer {
            cust_state,
            merchant_keys,
        }
        
    } 
    
    /// Produces a commitment to an invoice
    /// and a NIZK-PoK of the opening of the commitment
    pub fn prepare_payment_invoice<R: Rng>(
        &self, 
        invoice: &Invoice<E>, 
        rng: &mut R,
    ) -> Intermediary<E>
    {
        let r = util::convert_int_to_fr::<E>(rng.gen());
        let message = invoice.as_fr();
        let commit_key = &self.merchant_keys.invoice_commit;
        let invoice_commit = commit_key.commit(&message, &r);
        
        // PoK: prover knows the opening of the commitment
        // and reveals the invoice amount
        let proof = CommitmentProof::new(rng, commit_key, &invoice_commit.c, &message, &r, &vec![0]);
        Intermediary {
            invoice: invoice_commit,
            proof,
            nonce: None
        }
    }

    pub fn prepare_redemption_invoice<R: Rng>(
        &self,
        invoice: &Invoice<E>,
        rng: &mut R,
    ) -> Intermediary<E>
    {
        let r = util::convert_int_to_fr::<E>(rng.gen());
        let commit_key = &self.merchant_keys.invoice_commit;
        let message = invoice.as_fr();
        let invoice_commit = commit_key.commit(&message, &r);

        // PoK: prover knows the opening of the commitment
        // and reveals the invoice amount and nonce
        // TODO: and the prover has a valid credential for the provider_id
        // TODO: and the prover has a merchant signature on the opening of the commitment
        let proof = CommitmentProof::new(rng, commit_key, &invoice_commit.c, &message, &r, &vec![0,1]);
        Intermediary {
            invoice: invoice_commit,
            proof,
            nonce: Some(invoice.nonce),
        }
    }

    pub fn validate_invoice_signature(
        &self,
        invoice: Invoice<E>,
        signature: crypto::cl::Signature<E>,
    ) -> bool
    {
        self.merchant_keys.invoice_sign.verify(&self.merchant_keys.mpk, &invoice.as_fr(), &signature)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::ped92::{CSMultiParams,CSParams};
    use ff::{Field, Rand};
    use pairing::bls12_381::{Bls12, Fr, G1};
    use rand::thread_rng;
    use extensions::extension::Extensions;

    fn get_random_intermediary(with_nonce: bool) -> Intermediary<Bls12>{
        // get a commitment 
        let rng = &mut thread_rng();
        let csp = CSMultiParams::<Bls12>::setup_gen_params(rng, 5);
        let m1 = vec![Fr::rand(rng)];
        let r = Fr::rand(rng);
        let invoice = csp.commit(&m1, &r);

        // get a PoK
        let proof = CommitmentProof::new(rng, &csp, &invoice.c, &m1, &r, &vec![0]);

        // get a nonce
        let nonce = if with_nonce { Some(Fr::rand(rng)) }
            else { None };
        
        Intermediary {
            invoice,
            proof,
            nonce,
        }

    }    

    fn compare_intermediaries<E:Engine>(original: Intermediary<E>, result: Intermediary<E>) {
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
        let result = match Extensions::parse(&aux).unwrap() {
            Extensions::Intermediary(obj) => obj,
            _ => panic!("wrong extension type".to_string())
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
        let result = match Extensions::parse(&aux).unwrap() {
            Extensions::Intermediary(obj) => obj,
            _ => panic!("wrong extension type".to_string())
        };
       
        // check
        compare_intermediaries(original, result);
    }
}




