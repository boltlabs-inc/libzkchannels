pub mod extension;
pub mod spydermix;
pub mod intermediary;
use serde::{Deserialize, Serialize};

pub trait ExtensionInput {
    fn parse(aux: String) -> Option<Self> where Self: Sized;
}

pub trait ExtensionOutput {
    fn output(&self) -> Result<String, String>;
}