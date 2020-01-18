use super::*;
use pairing::Engine;
use ff::PrimeField;
use util::{hash_to_fr, hash_to_slice};
use std::fmt;
use serde::ser::{Serialize, Serializer, SerializeStruct};
use serde::de::{self, Deserialize, Deserializer, Visitor, MapAccess};
use channels_mpc::FixedSizeArray;

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
    pub nonce: [u8; NONCE_LEN], // 128-bits
    pub rev_lock: FixedSizeArray, // [u8; 32], // 32 bytes for hash
    pub bc: i64,
    pub bm: i64,
    pub escrow_txid: FixedSizeArray, // [u8; 32],
    pub escrow_prevout: FixedSizeArray, // [u8; 32],
    pub merch_txid: FixedSizeArray, // [u8; 32],
    pub merch_prevout: FixedSizeArray, // [u8; 32]
}

impl State {
//    pub fn generate_commitment(&self, t: &[u8; 32]) -> [u8; 32] {
//        let mut input_buf = Vec::new();
//        input_buf.extend_from_slice(&self.nonce);
//        input_buf.extend_from_slice(&self.rev_lock);
//        input_buf.extend_from_slice(&self.bc.to_string().as_bytes());
//        input_buf.extend_from_slice(&self.bm.to_string().as_bytes());
//        input_buf.extend_from_slice(&self.escrow_txid);
//        input_buf.extend_from_slice(&self.merch_txid);
//        input_buf.extend_from_slice(&self.escrow_prevout);
//        input_buf.extend_from_slice(&self.merch_prevout);
//
//        input_buf.extend_from_slice(t);
//
//        return hash_to_slice(&input_buf);
//    }

    pub fn serialize_compact(&self) -> Vec<u8> {
        let mut output_buf = Vec::new();
        output_buf.extend_from_slice(&self.nonce);
        output_buf.extend_from_slice(&self.rev_lock.0);
        output_buf.extend_from_slice(&self.bc.to_be_bytes());
        output_buf.extend_from_slice(&self.bm.to_be_bytes());
        output_buf.extend_from_slice(&self.merch_txid.0);
        output_buf.extend_from_slice(&self.escrow_txid.0);
        output_buf.extend_from_slice(&self.merch_prevout.0);
        output_buf.extend_from_slice(&self.escrow_prevout.0);

        return output_buf;
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let nonce_hex = hex::encode(self.nonce.to_vec());
        let rev_lock_hex = hex::encode(self.rev_lock.0.to_vec());
        let escrow_txid_hex = hex::encode(self.escrow_txid.0.to_vec());
        let escrow_prevout_hex = hex::encode(self.escrow_prevout.0.to_vec());

        let merch_txid_hex = hex::encode(self.merch_txid.0.to_vec());
        let merch_prevout_hex = hex::encode(self.merch_prevout.0.to_vec());

        write!(f, "State : (\nnonce={:?}\nrev_lock={:?}\nbc={}\nbm={}\nescrow_txid={:?}\nescrow_prevout={:?}\nmerch_txid={:?}\nmerch_prevout={:?}\n)",
               nonce_hex, rev_lock_hex, &self.bc, &self.bm, escrow_txid_hex, escrow_prevout_hex, merch_txid_hex, merch_prevout_hex)
    }
}

//impl ::serde::Serialize for State {
//    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error>
//    {
//        let mut state = s.serialize_struct("State", 8)?;
//        state.serialize_field("nonce", &hex::encode(&self.nonce))?;
//        state.serialize_field("rev_lock", &hex::encode(&self.rev_lock))?;
//        state.serialize_field("bc", &self.bc)?;
//        state.serialize_field("bm", &self.bm)?;
//        state.serialize_field("escrow_txid", &hex::encode(&self.escrow_txid))?;
//        state.serialize_field("merch_txid", &hex::encode(&self.merch_txid))?;
//        state.serialize_field("escrow_prevout", &hex::encode(&self.escrow_prevout))?;
//        state.serialize_field("merch_prevout", &hex::encode(&self.merch_prevout))?;
//        state.end()
//    }
//}
//
//impl<'de> Deserialize<'de> for State {
//    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//    where
//        D: Deserializer<'de>,
//    {
//        enum Field { Nonce, RevLock, CustBal, MerchBal, EscrowTxId, MerchTxId, EscrowPrevout, MerchPrevout };
//
//        impl<'de> Deserialize<'de> for Field {
//            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
//            where
//                D: Deserializer<'de>,
//            {
//                struct FieldVisitor;
//                impl<'de> Visitor<'de> for FieldVisitor {
//                    type Value = Field;
//
//                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                        formatter.write_str("`tx_fee` or `dust_limit`")
//                    }
//
//                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
//                    where
//                        E: de::Error,
//                    {
//                        match value {
//                            "nonce" => Ok(Field::Nonce),
//                            "rev_lock" => Ok(Field::RevLock),
//                            "bc" => Ok(Field::CustBal),
//                            "bm" => Ok(Field::MerchBal),
//                            "escrow_txid" => Ok(Field::EscrowTxId),
//                            "merch_txid" => Ok(Field::MerchTxId),
//                            "escrow_prevout" => Ok(Field::EscrowPrevout),
//                            "merch_prevout" => Ok(Field::MerchPrevout),
//                            _ => Err(de::Error::unknown_field(value, FIELDS)),
//                        }
//                    }
//                }
//
//                deserializer.deserialize_identifier(FieldVisitor)
//            }
//        }
//
//        struct StateVisitor;
//        impl<'de> Visitor<'de> for StateVisitor {
//            type Value = State;
//
//            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//                formatter.write_str("struct State")
//            }
//
//            fn visit_map<V>(self, mut map: V) -> Result<State, V::Error>
//            where
//                V: MapAccess<'de>
//            {
//                let mut nonce = [0u8; NONCE_LEN];
//                let mut rev_lock = [0u8; 32];
//                let mut escrow_txid = [0u8; 32];
//                let mut merch_txid = [0u8; 32];
//                let mut escrow_prevout = [0u8; 32];
//                let mut merch_prevout = [0u8; 32];
//                let mut cust_bal: Option<i64> = None;
//                let mut merch_bal: Option<i64> = None;
//
//                while let Some(key) = map.next_key()? {
//                    match key {
//                        Field::Nonce => {
//                            let _nonce: String = map.next_value()?;
//                            match hex::decode(_nonce.as_str()) {
//                                Ok(n) => nonce.copy_from_slice(&n),
//                                Err(e) => return Err(de::Error::missing_field("nonce"))
//                            };
//                        }
//                        Field::RevLock => {
//                            let rl: String = map.next_value()?;
//                            match hex::decode(rl.as_str()) {
//                                Ok(n) => rev_lock.copy_from_slice(&n),
//                                Err(e) => return Err(de::Error::missing_field("rev_lock"))
//                            };
//                        }
//                        Field::CustBal => {
//                            if cust_bal.is_some() {
//                                return Err(de::Error::duplicate_field("bc"));
//                            }
//                            cust_bal = map.next_value()?;
//                        }
//                        Field::MerchBal => {
//                            if merch_bal.is_some() {
//                                return Err(de::Error::duplicate_field("bm"));
//                            }
//                            merch_bal = map.next_value()?;
//                        }
//                        Field::EscrowTxId => {
//                            let txid: String = map.next_value()?;
//                            match hex::decode(txid.as_str()) {
//                                Ok(n) => escrow_txid.copy_from_slice(&n),
//                                Err(e) => return Err(de::Error::missing_field("escrow_txid"))
//                            };
//                        }
//                        Field::MerchTxId => {
//                            let txid: String = map.next_value()?;
//                            match hex::decode(txid.as_str()) {
//                                Ok(n) => merch_txid.copy_from_slice(&n),
//                                Err(e) => return Err(de::Error::missing_field("merch_txid"))
//                            };
//                        }
//                        Field::EscrowPrevout => {
//                            let prevout: String = map.next_value()?;
//                            match hex::decode(prevout.as_str()) {
//                                Ok(n) => escrow_prevout.copy_from_slice(&n),
//                                Err(e) => return Err(de::Error::missing_field("escrow_prevout"))
//                            };
//                        }
//                        Field::MerchPrevout => {
//                            let prevout: String = map.next_value()?;
//                            match hex::decode(prevout.as_str()) {
//                                Ok(n) => merch_prevout.copy_from_slice(&n),
//                                Err(e) => return Err(de::Error::missing_field("merch_prevout"))
//                            };
//                        }
//
//                    }
//                }
//
//                let bc = cust_bal.ok_or_else(|| de::Error::missing_field("bc"))?;
//                let bm = merch_bal.ok_or_else(|| de::Error::missing_field("bm"))?;
//                let state = State { nonce, rev_lock, bc, bm, escrow_txid, merch_txid, escrow_prevout, merch_prevout };
//                Ok(state)
//            }
//        }
//        const FIELDS: &'static [&'static str] = &["nonce", "rev_lock", "bc", "bm", "escrow_txid", "merch_txid", "escrow_prevout", "merch_prevout"];
//        deserializer.deserialize_struct("State", FIELDS, StateVisitor)
//    }
//}
