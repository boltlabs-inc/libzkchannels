use super::*;
use extensions::ExtensionOutput;
use extensions::spydermix::Spydermix;

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Extensions {
    #[serde(rename = "spydermix")]
    Spydermix(Spydermix),
    Default
}

impl ExtensionInput for Extensions {
    fn parse(aux: String) -> Option<Self> {
        match serde_json::from_str(aux.as_str()) {
            Ok(out) => Some(out),
            Err(e) => None
        }
    }
}

impl ExtensionOutput for Extensions {
    fn output(&self) -> Result<String, String> {
        match self {
            Extensions::Spydermix(obj) => {
                obj.output()
            }
            Extensions::Default => {
                Err("unimplemented".to_string())
            }
        }
    }
}