use super::*;
use extensions::ExtensionOutput;

#[derive(Clone, Serialize, Deserialize)]
pub struct Spydermix {
    amount: u64,
    duration: u64,
}

impl ExtensionOutput for Spydermix {
    fn output(&self) -> Result<String, String> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests{
    use super::*;
    use extensions::extension::Extensions;
    use pairing::bls12_381::Bls12;

    #[test]
    fn test_parse() {
        let result = Extensions::<Bls12>::parse(
            &"{\"type\": \"spydermix\", \"amount\": 10, \"duration\": 7}".to_string(),
            0);
        assert!(result.is_some());
        match result.unwrap() {
            Extensions::Spydermix(obj) => {
                assert_eq!(10, obj.amount);
                assert_eq!(7, obj.duration);
            },
            _ => {
                assert!(false);
            }
        }
    }
}