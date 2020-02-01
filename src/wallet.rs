use super::*;
use pairing::Engine;
use ff::PrimeField;
use util::hash_to_fr;
use std::fmt;
use fixed_size_array::{FixedSizeArray16, FixedSizeArray32};

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

pub const NONCE_LEN: usize = 16;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub nonce: FixedSizeArray16, // 128-bits
    pub rev_lock: FixedSizeArray32,
    pub bc: i64,
    pub bm: i64,
    pub escrow_txid: FixedSizeArray32,
    pub escrow_prevout: FixedSizeArray32,
    pub merch_txid: FixedSizeArray32,
    pub merch_prevout: FixedSizeArray32,
}

impl State {
    pub fn serialize_compact(&self) -> Vec<u8> {
        let mut output_buf = Vec::new();
        output_buf.extend_from_slice(&self.nonce.0);
        output_buf.extend_from_slice(&self.rev_lock.0);
        output_buf.extend_from_slice(&self.bc.to_be_bytes());
        output_buf.extend_from_slice(&self.bm.to_be_bytes());
        output_buf.extend_from_slice(&self.merch_txid.0);
        output_buf.extend_from_slice(&self.escrow_txid.0);
        output_buf.extend_from_slice(&self.merch_prevout.0);
        output_buf.extend_from_slice(&self.escrow_prevout.0);

        return output_buf;
    }

    pub fn get_nonce(&self) -> [u8; NONCE_LEN] {
        self.nonce.0
    }

    pub fn get_rev_lock(&self) -> [u8; 32] {
        self.rev_lock.0
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let nonce_hex = hex::encode(self.nonce.0.to_vec());
        let rev_lock_hex = hex::encode(self.rev_lock.0.to_vec());
        let escrow_txid_hex = hex::encode(self.escrow_txid.0.to_vec());
        let escrow_prevout_hex = hex::encode(self.escrow_prevout.0.to_vec());

        let merch_txid_hex = hex::encode(self.merch_txid.0.to_vec());
        let merch_prevout_hex = hex::encode(self.merch_prevout.0.to_vec());

        write!(f, "State : (\nnonce={:?}\nrev_lock={:?}\nbc={}\nbm={}\nescrow_txid={:?}\nescrow_prevout={:?}\nmerch_txid={:?}\nmerch_prevout={:?}\n)",
               nonce_hex, rev_lock_hex, &self.bc, &self.bm, escrow_txid_hex, escrow_prevout_hex, merch_txid_hex, merch_prevout_hex)
    }
}
