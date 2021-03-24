use extensions::ExtensionOutput;

#[derive(Clone, Serialize, Deserialize)]
pub struct Intermediary {

}

impl ExtensionOutput for Intermediary {
    fn output(&self) -> Result<String, String> {
        unimplemented!()
    }
}