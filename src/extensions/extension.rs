use super::*;
use extensions::ExtensionOutput;
use extensions::spydermix::Spydermix;
use extensions::intermediary::Intermediary;
use pairing::Engine;

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
pub enum Extensions<E: Engine> {
    #[serde(rename = "spydermix")]
    Spydermix(Spydermix),
    #[serde(rename = "intermediary")]
    Intermediary(Intermediary<E>),
    Default
}

impl<'de, E: Engine> ExtensionInput<'de, E> for Extensions<E> {
    fn parse(aux: &'de String) -> Option<Self> where
        <E as pairing::Engine>::G1: serde::Deserialize<'de>,
        <E as pairing::Engine>::G2: serde::Deserialize<'de>,
        <E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>,
    {
        match serde_json::from_str::<Extensions<E>>(aux.as_str()) {
            Ok(out) => {
                out.init();
                Some(out)
            },
            Err(e) => {
                println!("{}", e);
                None
            }
        }
    }
}

impl<E: Engine> ExtensionInit for Extensions<E> {
    fn init(&self) {
        match self {
            Extensions::Intermediary(obj) => {
                obj.init()
            }
            _ => {}
        }
    }
}

impl<E: Engine> ExtensionOutput for Extensions<E> {
    fn output(&self) -> Result<String, String> {
        match self {
            Extensions::Spydermix(obj) => {
                obj.output()
            }
            Extensions::Default => {
                Err("unimplemented".to_string())
            }
            Extensions::Intermediary(obj) => {
                obj.output()
            }
        }
    }
}