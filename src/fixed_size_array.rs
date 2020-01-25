use super::*;
use serde::de::{self, Deserialize, Deserializer, Visitor};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FixedSizeArray16(pub [u8; 16]);

impl ::serde::Serialize for FixedSizeArray16 {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error>
    {
        s.collect_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for FixedSizeArray16 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArray16Visitor;
        impl<'de> Visitor<'de> for FixedSizeArray16Visitor {
            type Value = FixedSizeArray16;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct FixedSizeArray16")
            }

            #[inline]
            fn visit_str<V>(self, v: &str) -> Result<FixedSizeArray16, V>
                where V: ::serde::de::Error
            {
                let bytes = match hex::decode(&v) {
                    Ok(n) => n,
                    Err(e) => return Err(de::Error::custom(e.to_string()))
                };
                let mut fixed_bytes = [0u8; 16];
                match bytes.len() == 16 {
                    true => fixed_bytes.copy_from_slice(&bytes),
                    false => return Err(de::Error::custom("invalid length"))
                }
                Ok(FixedSizeArray16(fixed_bytes))
            }
        }
        deserializer.deserialize_str(FixedSizeArray16Visitor { })
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct FixedSizeArray32(pub [u8; 32]);

impl ::serde::Serialize for FixedSizeArray32 {
    fn serialize<S: ::serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error>
    {
        s.collect_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for FixedSizeArray32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FixedSizeArray32Visitor;
        impl<'de> Visitor<'de> for FixedSizeArray32Visitor {
            type Value = FixedSizeArray32;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct FixedSizeArray32")
            }

            #[inline]
            fn visit_str<V>(self, v: &str) -> Result<FixedSizeArray32, V>
                where V: ::serde::de::Error
            {
                let bytes = match hex::decode(&v) {
                    Ok(n) => n,
                    Err(e) => return Err(de::Error::custom(e.to_string()))
                };
                let mut fixed_bytes = [0u8; 32];
                match bytes.len() == 32 {
                    true => fixed_bytes.copy_from_slice(&bytes),
                    false => return Err(de::Error::custom("invalid length"))
                }
                Ok(FixedSizeArray32(fixed_bytes))
            }
        }
        deserializer.deserialize_str(FixedSizeArray32Visitor { })
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
        s.collect_str(&hex::encode(&self.get_bytes()))
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
                formatter.write_str("struct FixedSizeArray64")
            }

            #[inline]
            fn visit_str<V>(self, v: &str) -> Result<FixedSizeArray64, V>
                where V: ::serde::de::Error
            {
                let bytes = match hex::decode(&v) {
                    Ok(n) => n,
                    Err(e) => return Err(de::Error::custom(e.to_string()))
                };
                let mut fixed_bytes1 = [0u8; 32];
                let mut fixed_bytes2 = [0u8; 32];
                match bytes.len() == 64 {
                    true => {
                        fixed_bytes1.copy_from_slice(&bytes[0..32]);
                        fixed_bytes2.copy_from_slice(&bytes[32..64])
                    },
                    false => return Err(de::Error::custom("invalid length: expected 64 bytes"))
                }
                Ok(FixedSizeArray64(fixed_bytes1, fixed_bytes2))
            }

        }
        deserializer.deserialize_str(FixedSizeArray64Visitor { })
    }
}
