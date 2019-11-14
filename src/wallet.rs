extern crate pairing;

use super::*;
use pairing::Engine;
use ff::PrimeField;
use util::{hash_to_fr, hash_to_slice};
use std::fmt;

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "<E as ff::ScalarEngine>::Fr: serde::Serialize"))]
#[serde(bound(deserialize = "<E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>"))]
pub struct Wallet<E: Engine> {
    pub channelId: E::Fr,
    pub wpk: E::Fr,
    pub bc: i64,
    pub bm: i64,
    pub close: Option<E::Fr>,
}

impl<E: Engine> Wallet<E> {
    pub fn as_fr_vec(&self) -> Vec<E::Fr> {
        if self.close.is_some() {
            vec!(self.channelId, self.wpk, E::Fr::from_str(&self.bc.to_string()).unwrap(), E::Fr::from_str(&self.bm.to_string()).unwrap(), self.close.unwrap())
        } else {
            vec!(self.channelId, self.wpk, E::Fr::from_str(&self.bc.to_string()).unwrap(), E::Fr::from_str(&self.bm.to_string()).unwrap())
        }
    }

    pub fn without_close(&self) -> Vec<E::Fr> {
        vec!(self.channelId, self.wpk, E::Fr::from_str(&self.bc.to_string()).unwrap(), E::Fr::from_str(&self.bm.to_string()).unwrap())
    }

    pub fn with_close(&mut self, msg: String) -> Vec<E::Fr> {
        let m = hash_to_fr::<E>(msg.into_bytes() );
        self.close = Some(m.clone());
        return self.as_fr_vec();
    }
}

impl<E: Engine> fmt::Display for Wallet<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.close.is_some() {
            let close_str = self.close.unwrap();
            write!(f, "Wallet : (\nchannelId={}\nwpk={}\nbc={}\nbm={}\nclose={}\n)", &self.channelId, &self.wpk, &self.bc, &self.bm, close_str)
        } else {
            write!(f, "Wallet : (\nchannelId={}\nwpk={}\nbc={}\nbm={}\nclose=None\n)", &self.channelId, &self.wpk, &self.bc, &self.bm)
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    pub rev_lock: secp256k1::PublicKey,
    pub pk_c: secp256k1::PublicKey,
    pub pk_m: secp256k1::PublicKey,
    pub bc: i64,
    pub bm: i64,
    pub escrow_txid: [u8; 32],
    pub merch_txid: [u8; 32]
}

impl State {
    pub fn generate_commitment(&self) -> [u8; 32] {
        let mut input_buf = Vec::new();
        input_buf.extend_from_slice(&self.rev_lock.serialize_uncompressed());
        input_buf.extend_from_slice(&self.pk_c.serialize_uncompressed());
        input_buf.extend_from_slice(&self.pk_m.serialize_uncompressed());
        input_buf.extend_from_slice(&self.bc.to_string().as_bytes());
        input_buf.extend_from_slice(&self.bm.to_string().as_bytes());
        input_buf.extend_from_slice(&self.escrow_txid);
        input_buf.extend_from_slice(&self.merch_txid);

        return hash_to_slice(&input_buf);
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "State : (\nrev_lock={}\npk_c={:?}\npk_m={:?}\nbc={}\nbm={}\nescrow_txid={:?}\nmerch_txid={:?}\n)",
               &self.rev_lock, &self.pk_c, &self.pk_m, &self.bc, &self.bm, &self.escrow_txid, &self.merch_txid)
    }
}
