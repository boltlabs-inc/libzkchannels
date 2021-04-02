pub mod extension;
pub mod spydermix;
pub mod intermediary;

use serde::{Deserialize, Serialize, Serializer};
use pairing::Engine;
use super::downcast_rs::Downcast;
use serde::ser::SerializeStruct;
use secp256k1::serde::Deserializer;

pub trait ExtensionInput<'de, E: Engine> {
    fn parse(aux: &'de String, payment_amount: i64) -> Option<Self> where Self: Sized,
                                                                          <E as pairing::Engine>::G1: serde::Deserialize<'de>,
                                                                          <E as pairing::Engine>::G2: serde::Deserialize<'de>,
                                                                          <E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>,
                                                                          <E as pairing::Engine>::Fqk: serde::Deserialize<'de>,;
}

pub trait ExtensionTrait {
    fn init(&self, payment_amount: i64, ei: Box<dyn ExtensionInfoWrapper>) -> Result<(), String>;
    fn output(&self) -> Result<String, String>;
}

pub trait ExtensionInfoWrapper: Downcast {}
impl_downcast!(ExtensionInfoWrapper);

// impl Serialize for ExtensionInfoWrapper {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where S: Serializer {
//         let s = serializer.serialize_struct("???", 3)?;
//
//         s.end()
//     }
// }
//
// impl<'de> Deserialize<'de> for ExtensionInfoWrapper where
//     Self: Sized {
//     fn deserialize<D>(deserializer: D) -> Result<Self, <D as Deserializer<'de>>::Error> where
//         D: Deserializer<'de> {
//         unimplemented!()
//     }
// }