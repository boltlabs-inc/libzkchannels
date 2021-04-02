use super::*;
use extensions::spydermix::Spydermix;
use extensions::intermediary::Intermediary;
use pairing::Engine;

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
#[serde(tag = "type")]
pub enum Extensions<E: Engine> {
    #[serde(rename = "spydermix")]
    Spydermix(Spydermix),
    #[serde(rename = "intermediary")]
    Intermediary(Intermediary<E>),
    Default,
}

pub trait ExtensionWrapper<'de, E: Engine> {
    fn init(&self, payment_amount: i64, ei: &mut HashMap<String, ExtensionInfoWrapper<E>>) -> Result<(), String> where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
        <E as pairing::Engine>::Fqk: serde::Serialize,;
    fn output<R: Rng>(&self, rng: &mut R, ei: &HashMap<String, ExtensionInfoWrapper<E>>) -> Result<String, String> where
        <E as pairing::Engine>::G1: serde::Serialize,;
}

impl<'de, E: Engine> ExtensionInput<'de, E> for Extensions<E> {
    fn parse(aux: &'de String, payment_amount: i64, extension_info: &mut HashMap<String, ExtensionInfoWrapper<E>>) -> Result<Option<Self>, String>
        where
            <E as pairing::Engine>::G1: serde::Serialize,
            <E as pairing::Engine>::G2: serde::Serialize,
            <E as ff::ScalarEngine>::Fr: serde::Serialize,
            <E as pairing::Engine>::Fqk: serde::Serialize,
            <E as pairing::Engine>::G1: serde::Deserialize<'de>,
            <E as pairing::Engine>::G2: serde::Deserialize<'de>,
            <E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>,
            <E as pairing::Engine>::Fqk: serde::Deserialize<'de>,
    {
        if aux.is_empty() {
            return Ok(None);
        }
        match serde_json::from_str::<Extensions<E>>(aux.as_str()) {
            Ok(out) => {
                out.init(payment_amount, extension_info)?;
                Ok(Some(out))
            }
            Err(e) => {
                Err(e.to_string())
            }
        }
    }
}

impl<'de, E: Engine> ExtensionWrapper<'de, E> for Extensions<E> {
    fn init(&self, payment_amount: i64, ei: &mut HashMap<String, ExtensionInfoWrapper<E>>) -> Result<(), String> where
        <E as pairing::Engine>::G1: serde::Serialize,
        <E as pairing::Engine>::G2: serde::Serialize,
        <E as ff::ScalarEngine>::Fr: serde::Serialize,
        <E as pairing::Engine>::Fqk: serde::Serialize, {
        match self {
            Extensions::Intermediary(obj) => {
                obj.init(payment_amount, ei.get_mut("intermediary").unwrap_or(&mut ExtensionInfoWrapper::Default))
            }
            _ => { Ok(()) }
        }
    }

    fn output<R: Rng>(&self, rng: &mut R, ei: &HashMap<String, ExtensionInfoWrapper<E>>) -> Result<String, String> where
        <E as pairing::Engine>::G1: serde::Serialize,
    {
        match self {
            Extensions::Spydermix(_) => {
                Err("unimplemented".to_string())
            }
            Extensions::Default => {
                Ok("".to_string())
            }
            Extensions::Intermediary(obj) => {
                if !obj.is_claim() {
                    obj.output(rng, ei.get("intermediary").unwrap_or(&ExtensionInfoWrapper::Default))
                } else {
                    Ok("".to_string())
                }
            }
        }
    }
}