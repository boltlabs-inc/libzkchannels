use super::*;

#[derive(Clone, Serialize, Deserialize)]
pub struct Spydermix {
    amount: u64,
    duration: u64,
}

impl<'de, E: Engine> ExtensionTrait<'de, E> for Spydermix {
    fn init(&self, _payment_amount: i64, ei: &ExtensionInfoWrapper<E>)  -> Result<(), String> { unimplemented!() }
    fn output(&self, ei: &ExtensionInfoWrapper<E>) -> Result<String, String> {
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
            0, HashMap::new());
        assert!(result.is_ok());
        let unwrapped_result = result.unwrap();
        assert!(unwrapped_result.is_some());
        match unwrapped_result.unwrap() {
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