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
    fn init(&self, payment_amount: i64, ei: HashMap<String, ExtensionInfoWrapper<E>>) -> Result<(), String>;
    fn output(&self, ei: HashMap<String, ExtensionInfoWrapper<E>>) -> Result<String, String>;
}

impl<'de, E: Engine> ExtensionInput<'de, E> for Extensions<E> {
    fn parse(aux: &'de String, payment_amount: i64, extension_info: HashMap<String, ExtensionInfoWrapper<E>>) -> Result<Option<Self>, String>
        where
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
    fn init(&self, payment_amount: i64, ei: HashMap<String, ExtensionInfoWrapper<E>>) -> Result<(), String> {
        match self {
            Extensions::Intermediary(obj) => {
                obj.init(payment_amount, ei.get("intermediary").unwrap_or(&ExtensionInfoWrapper::Default))
            }
            _ => { Ok(()) }
        }
    }

    fn output(&self, ei: HashMap<String, ExtensionInfoWrapper<E>>) -> Result<String, String> {
        match self {
            Extensions::Spydermix(obj) => {
                Err("unimplemented".to_string())
            }
            Extensions::Default => {
                Err("unimplemented".to_string())
            }
            Extensions::Intermediary(obj) => {
                obj.output(ei.get("intermediary").unwrap_or(&ExtensionInfoWrapper::Default))
            }
        }
    }
}