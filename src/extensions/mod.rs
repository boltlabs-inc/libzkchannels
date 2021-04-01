pub mod extension;
pub mod spydermix;
pub mod intermediary;
use serde::{Deserialize, Serialize};
use pairing::Engine;

pub trait ExtensionInput<'de, E: Engine> {
    fn parse(aux: &'de String, payment_amount: i64) -> Option<Self> where Self: Sized,
    <E as pairing::Engine>::G1: serde::Deserialize<'de>,
    <E as pairing::Engine>::G2: serde::Deserialize<'de>,
    <E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>,
    <E as pairing::Engine>::Fqk: serde::Deserialize<'de>,;
}

pub trait ExtensionTrait {
    fn init(&self, payment_amount: i64) -> Result<(), String>;
    fn output(&self) -> Result<String, String>;
}