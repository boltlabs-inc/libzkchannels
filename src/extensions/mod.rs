pub mod extension;
pub mod spydermix;
pub mod intermediary;

use serde::{Deserialize, Serialize};
use pairing::Engine;
use extensions::intermediary::IntermediaryMerchantInfo;
use std::collections::HashMap;

pub trait ExtensionInput<'de, E: Engine> {
    fn parse(aux: &'de String, payment_amount: i64, extension_info: HashMap<String, ExtensionInfoWrapper<E>>) -> Result<Option<Self>, String> where Self: Sized,
                                                                                                                                                    <E as pairing::Engine>::G1: serde::Serialize,
                                                                                                                                                    <E as pairing::Engine>::G2: serde::Serialize,
                                                                                                                                                    <E as pairing::Engine>::Fqk: serde::Serialize,
                                                                                                                                                    <E as pairing::Engine>::G1: Deserialize<'de>,
                                                                                                                                                    <E as pairing::Engine>::G2: Deserialize<'de>,
                                                                                                                                                    <E as ff::ScalarEngine>::Fr: Deserialize<'de>,
                                                                                                                                                    <E as pairing::Engine>::Fqk: Deserialize<'de>,;
}

pub trait ExtensionTrait<'de, E: Engine> {
    fn init(&self, payment_amount: i64, ei: &ExtensionInfoWrapper<E>) -> Result<(), String> where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as pairing::Engine>::Fqk: serde::Serialize,;
    fn output(&self, ei: &ExtensionInfoWrapper<E>) -> Result<String, String>;
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
#[serde(tag = "type")]
pub enum ExtensionInfoWrapper<E: Engine> {
    #[serde(rename = "intermediary")]
    Intermediary(IntermediaryMerchantInfo<E>),
    Default,
}