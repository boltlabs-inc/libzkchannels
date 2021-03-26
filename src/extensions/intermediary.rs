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
    proof: CommitmentProof<E>
}

impl<E: Engine> ExtensionInit for Intermediary<E> {
    fn init(&self) {}
}

impl<E: Engine> ExtensionOutput for Intermediary<E> {
    fn output(&self) -> Result<String, String> {
        unimplemented!()
    }
}

/// Invoice object
pub struct Invoice<E:Engine> {
    pub amount: i64,
    nonce: E::Fr,
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
    /// holds basic channel state (maybe this shouldn't exist?)
    pub channel_state: zkproofs::ChannelState<E>,
    //pub channel_token: ChannelToken<E>,
    /// merchant public parameters 
    mpk: crypto::cl::PublicParams<E>,
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
    ) -> (Self, ChannelToken<E>) {
        let (channel_token, merch_state, channel_state) =
            zkproofs::merchant_init(csprng, channel_state, name);
        
        // create additional keys used in intermediary protocol
        let mpk = channel_token.mpk.clone();
        let keypair_ac = crypto::cl::BlindKeyPair::<E>::generate(csprng, &mpk, 1);
        let keypair_inv = crypto::cl::BlindKeyPair::<E>::generate(csprng, &mpk, 3);
        
        (IntermediaryMerchant {
            merch_state,
            channel_state,
            mpk,
            keypair_ac,
            keypair_inv,
        },
        channel_token)
    }

    /// produces the public key (generators) for the invoice keypair
    pub fn get_invoice_public_keys(&self) -> crypto::ped92::CSMultiParams<E> {
        self.keypair_inv.generate_cs_multi_params(&self.mpk)
    }
}

/// Intermediary customer; acts as a zkChannels customer
/// makes payments via an IntermediaryMerchant
/// Holds extra key material from IM.
pub struct IntermediaryCustomer<E:Engine> {
    /// holds the customer state
    pub cust_state: zkproofs::CustomerState<E>,
    /// holds the merchant public keys for committing an invoice
    pubkey_inv: crypto::ped92::CSMultiParams<E>,
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

        IntermediaryCustomer {
            cust_state,
            pubkey_inv: merch.get_invoice_public_keys(),
        }
        
    } 
    
    /// Produces a commitment to an invoice
    /// and a NIZK-PoK of the opening of the commitment
    pub fn prepare_invoice<R: Rng>(
        &self, 
        invoice: &Invoice<E>, 
        rng: &mut R,
    ) -> (Commitment<E>, CommitmentProof<E>) 
    {
        let r = util::convert_int_to_fr::<E>(rng.gen());
        let message = invoice.as_fr();
        let invoice_commit = self.pubkey_inv.commit(&message, &r);
        
        let proof = CommitmentProof::new(rng, &self.pubkey_inv, &invoice_commit.c, &message, &r, &vec![0]);
        (invoice_commit, proof)
    }
}
