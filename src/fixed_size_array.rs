use super::*;
use serde::ser::{Serialize, Serializer, SerializeTuple, SerializeStruct};
use serde::de::{self, Deserialize, Deserializer, Visitor, SeqAccess, MapAccess};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FixedSizeArray(pub [u8; 32]);

impl ::serde::Serialize for FixedSizeArray {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error>
    {
        let mut tup = s.serialize_tuple(1)?;
        tup.serialize_element(&hex::encode(&self.0))?;
        tup.end()
    }
}

impl<'de> Deserialize<'de> for FixedSizeArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArrayVisitor;
        impl<'de> Visitor<'de> for FixedSizeArrayVisitor {
            type Value = FixedSizeArray;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct FixedSizeArray")
            }

            #[inline]
            fn visit_seq<V>(self, mut seq: V) -> Result<FixedSizeArray, V::Error>
                where V: SeqAccess<'de>
            {
                let hex_str = seq.next_element::<String>()?;
                let bytes = match hex_str {
                    Some(n) => hex::decode(n.as_str()),
                    None => return Err(de::Error::custom("No string was found"))
                };
                let mut fixed_bytes = [0u8; 32];
                match bytes.is_ok() {
                    true => fixed_bytes.copy_from_slice(&bytes.unwrap()),
                    false => return Err(de::Error::custom("invalid hex encoding"))
                }
                Ok(FixedSizeArray(fixed_bytes))
            }
        }
        deserializer.deserialize_seq(FixedSizeArrayVisitor { })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FixedSizeArray64(pub [u8; 32], pub [u8; 32]);

impl FixedSizeArray64 {
    pub fn new(buf: [u8; 64]) -> Self {
        let mut b1 = [0u8; 32];
        let mut b2 = [0u8; 32];
        b1.copy_from_slice(&buf[0..32]);
        b2.copy_from_slice(&buf[32..64]);
        FixedSizeArray64(b1, b2)
    }

    pub fn get_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&self.0);
        b.extend_from_slice(&self.1);
        return b;
    }
}

impl ::serde::Serialize for FixedSizeArray64 {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error>
    {
        let mut tup = s.serialize_tuple(1)?;
        tup.serialize_element(&hex::encode(&self.get_bytes()))?;
        tup.end()
    }
}

impl<'de> Deserialize<'de> for FixedSizeArray64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArray64Visitor;
        impl<'de> Visitor<'de> for FixedSizeArray64Visitor {
            type Value = FixedSizeArray64;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct FixedSizeArray")
            }

            #[inline]
            fn visit_seq<V>(self, mut seq: V) -> Result<FixedSizeArray64, V::Error>
                where V: SeqAccess<'de>
            {
                let hex_str = seq.next_element::<String>()?;
                let bytes = match hex_str {
                    Some(n) => hex::decode(n.as_str()),
                    None => return Err(de::Error::custom("No string was found"))
                };
                let mut fixed_bytes1 = [0u8; 32];
                let mut fixed_bytes2 = [0u8; 32];

                match bytes.is_ok() {
                    true => {
                        let b = bytes.unwrap();
                        if b.len() != 64 {
                            return Err(de::Error::custom("invalid length: expected 64 bytes"));
                        }
                        fixed_bytes1.copy_from_slice(&b[0..32]);
                        fixed_bytes2.copy_from_slice(&b[32..64])
                    },
                    false => return Err(de::Error::custom("invalid hex encoding"))
                }
                Ok(FixedSizeArray64(fixed_bytes1, fixed_bytes2))
            }
        }
        deserializer.deserialize_seq(FixedSizeArray64Visitor { })
    }
}
