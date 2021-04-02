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

impl<'de, E: Engine> ExtensionInput<'de, E> for Extensions<E> {
    fn parse(aux: &'de String, payment_amount: i64) -> Option<Self> where
        <E as pairing::Engine>::G1: serde::Deserialize<'de>,
        <E as pairing::Engine>::G2: serde::Deserialize<'de>,
        <E as ff::ScalarEngine>::Fr: serde::Deserialize<'de>,
        <E as pairing::Engine>::Fqk: serde::Deserialize<'de>,
    {
        match serde_json::from_str::<Extensions<E>>(aux.as_str()) {
            Ok(out) => {
                // out.init(payment_amount, Box::new(""));
                Some(out)
            },
            Err(e) => {
                println!("{}", e);
                None
            }
        }
    }
}

impl<E: Engine> ExtensionTrait for Extensions<E> {
    fn init(&self, payment_amount: i64, ei: Box<dyn ExtensionInfoWrapper>) -> Result<(), String> {
        match self {
            Extensions::Intermediary(obj) => {
                obj.init(payment_amount, ei)
            }
            _ => { Ok(()) }
        }
    }

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